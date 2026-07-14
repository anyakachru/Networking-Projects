package edu.wisc.cs.sdn.vnet.rt;

import net.floodlightcontroller.packet.MACAddress;
import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.ICMP;

import java.util.*;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device {
    /** Routing table for the router */
    protected RouteTable routeTable;

    /** ARP cache for the router */
    protected ArpCache arpCache;

    private final boolean dbg = false;
    private RipProtocolHandler ripHandler;
    private boolean ripStarted = false;

    private static final byte[] BCAST_MAC = new byte[] { (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF };
    private static final int MCAST_RIP_IP = IPv4.toIPv4Address("224.0.0.9");
    private static final int REQ_RIP = 1;
    private static final int RESP_RIP = 2;
    private static final int UNSOLICITED_RIP = 3;

    /**
     * Creates a router for a specific host.
     * @param host hostname for the router
     */
    public Router(String host, DumpFile logfile) {
        super(host, logfile);
        this.routeTable = new RouteTable();
        this.arpCache = new ArpCache();
        this.ripHandler = new RipProtocolHandler();
        this.ripHandler.startRIP();
    }

    /**
     * @return routing table for the router
     */
    public RouteTable getRouteTable() { 
        return this.routeTable; 
    }

    /**
     * Load a new routing table from a file.
     * @param staticRoutesFile the name of the file containing the routing table
     */
    public void loadRouteTable(String staticRoutesFile) {
        if (!routeTable.load(staticRoutesFile, this)) {
            System.err.println("Error setting up routing table from file " + staticRoutesFile);
            System.exit(1);
        }

        System.out.println("Loaded static route table");
        System.out.println("-------------------------------------------------");
        System.out.print(this.routeTable.toString());
        System.out.println("-------------------------------------------------");
        System.out.println("ROUTING TABLE:\n" + this.routeTable.toString());
    }

    /**
     * Load a new ARP cache from a file.
     * @param staticArpFile the name of the file containing the ARP cache
     */
    public void loadArpCache(String staticArpFile) {
        if (!arpCache.load(staticArpFile)) {
            System.err.println("Error setting up ARP cache from file " + staticArpFile);
            System.exit(1);
        }

        System.out.println("Loaded static ARP cache");
        System.out.println("----------------------------------");
        System.out.print(this.arpCache.toString());
        System.out.println("----------------------------------");
    }

    /**
     * Handle an Ethernet packet received on a specific interface.
     * @param inboundFrame the Ethernet packet that was received
     * @param ingressPort the interface on which the packet was received
     */
    public void handlePacket(Ethernet inboundFrame, Iface ingressPort) {
        if (!ripStarted) {
        ripStarted = true;
        ripHandler.startRIP();
        System.out.println("Start rip");
        }

        System.out.println("EtherType: " + inboundFrame.getEtherType());
        System.out.println("Dest MAC: " + inboundFrame.getDestinationMAC());
        if (inboundFrame == null || ingressPort == null) {
            return;
        }

        System.out.println("*** ROUTER RECEIVED A PACKET ON " + ingressPort.getName() + " ***");

        switch (inboundFrame.getEtherType()) {
            case Ethernet.TYPE_IPv4:
                System.out.println("IPv4 handler");
                this.routeIpv4Datagram(inboundFrame, ingressPort);
                break;

            case Ethernet.TYPE_ARP:
                System.out.println("ARP handler");
                this.processArpMessage(inboundFrame, ingressPort);
                break;

            default:
                System.out.println("-> Dropping unknown packet type: " + inboundFrame.getEtherType());
                break;
        }
    }

    public void handleMissingArp(int targetIpGw, Ethernet inboundFrame, Iface ingressPort, Iface egressPort) {
        ARP arpQuery = new ARP();
        arpQuery.setHardwareType(ARP.HW_TYPE_ETHERNET);
        arpQuery.setProtocolType(Ethernet.TYPE_IPv4);
        arpQuery.setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH);
        arpQuery.setProtocolAddressLength((byte) 4);
        arpQuery.setOpCode(ARP.OP_REQUEST);
        
        // Sender is THIS router
        arpQuery.setSenderHardwareAddress(egressPort.getMacAddress().toBytes());
        arpQuery.setSenderProtocolAddress(egressPort.getIpAddress());
        
        // Target is the nextHop IP (Target MAC is unknown/zeros)
        arpQuery.setTargetHardwareAddress(new byte[6]); 
        arpQuery.setTargetProtocolAddress(targetIpGw);

        // Wrap in Ethernet Frame
        Ethernet ethernetWrapper = new Ethernet();
        ethernetWrapper.setEtherType(Ethernet.TYPE_ARP);
        ethernetWrapper.setSourceMACAddress(egressPort.getMacAddress().toBytes());
        ethernetWrapper.setDestinationMACAddress(BCAST_MAC); 
        ethernetWrapper.setPayload(arpQuery);

        // Broadcast it
        this.sendPacket(ethernetWrapper, egressPort);
    }

    private void processArpMessage(Ethernet inboundFrame, Iface ingressPort) {
        if (!(inboundFrame.getPayload() instanceof ARP)) {
            return; 
        }

        ARP arpData = (ARP) inboundFrame.getPayload();
        int senderIp = IPv4.toIPv4Address(arpData.getSenderProtocolAddress());
        MACAddress senderMac = new MACAddress(arpData.getSenderHardwareAddress());

        this.arpCache.insert(senderMac, senderIp);

        if (arpData.getOpCode() != ARP.OP_REQUEST) {
            return;
        }

        int reqTargetIp = IPv4.toIPv4Address(arpData.getTargetProtocolAddress());
        
        if (reqTargetIp == ingressPort.getIpAddress()) {
            ARP arpResponse = new ARP();
            arpResponse.setHardwareType(ARP.HW_TYPE_ETHERNET);
            arpResponse.setProtocolType(Ethernet.TYPE_IPv4);
            arpResponse.setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH);
            arpResponse.setProtocolAddressLength((byte) 4);
            arpResponse.setOpCode(ARP.OP_REPLY);
            
            arpResponse.setSenderHardwareAddress(ingressPort.getMacAddress().toBytes());
            arpResponse.setSenderProtocolAddress(ingressPort.getIpAddress());
            
            arpResponse.setTargetHardwareAddress(arpData.getSenderHardwareAddress());
            arpResponse.setTargetProtocolAddress(arpData.getSenderProtocolAddress());

            Ethernet replyEthFrame = new Ethernet();
            replyEthFrame.setEtherType(Ethernet.TYPE_ARP);
            replyEthFrame.setSourceMACAddress(ingressPort.getMacAddress().toBytes());
            replyEthFrame.setDestinationMACAddress(inboundFrame.getSourceMACAddress());
            replyEthFrame.setPayload(arpResponse);

            this.sendPacket(replyEthFrame, ingressPort);
        }
    }

    private void forwardIpPacket(Ethernet inboundFrame, Iface ingressPort) {
        IPv4 ipv4Payload = (IPv4) inboundFrame.getPayload();
        RouteEntry forwardingEntry = Router.this.routeTable.lookup(ipv4Payload.getDestinationAddress());

        if (forwardingEntry == null) {

        //System.out.println(" No route found in routeTable!"); 
        System.out.println("DROP: No route found for IP: " + IPv4.fromIPv4Address(ipv4Payload.getDestinationAddress()));  
        System.out.println("=== ROUTING TABLE ===");
        System.out.println(Router.this.routeTable.toString());

          dispatchIcmp(3, 0, inboundFrame, ingressPort); // Net Unreachable
            
            return;
        }

        Iface egressPort = forwardingEntry.getInterface();
        if (egressPort == ingressPort) return;

        int nextHopIp = (forwardingEntry.getGatewayAddress() == 0) ? ipv4Payload.getDestinationAddress() : forwardingEntry.getGatewayAddress();
        ArpEntry resolvedMacEntry = Router.this.arpCache.lookup(nextHopIp);

        if (resolvedMacEntry == null) {
            
        System.out.println("Drop Sending ARP Request instead.");
        Router.this.handleMissingArp(nextHopIp, inboundFrame, ingressPort, egressPort);
                    return;
                }

        inboundFrame.setSourceMACAddress(egressPort.getMacAddress().toBytes());
        inboundFrame.setDestinationMACAddress(resolvedMacEntry.getMac().toBytes());
        Router.this.sendPacket(inboundFrame, egressPort);
        System.out.println("Packet forwarded out " + egressPort.getName());    

    }

    private void dispatchIcmp(int type, int code, Ethernet inboundFrame, Iface ingressPort) {
        IPv4 ipPacket = (IPv4) inboundFrame.getPayload();

        Data data;
        if (type == 0) {
            // Echo reply: mirror back the original ICMP payload data
            data = new Data(ipPacket.getPayload().getPayload().serialize());
        } else {
            // Error messages: 4 bytes padding + original IP header + first 8 bytes of data
            byte[] icmpDataBytes = new byte[4 + ipPacket.getHeaderLength() * 4 + 8];
            System.arraycopy(ipPacket.serialize(), 0, icmpDataBytes, 4, icmpDataBytes.length - 4);
            data = new Data(icmpDataBytes);
        }

        ICMP icmp = (ICMP) new ICMP()
                .setIcmpType((byte) type)
                .setIcmpCode((byte) code)
                .setPayload(data);

        IPv4 icmpIp = (IPv4) new IPv4()
                .setVersion((byte) 4)
                .setTtl((byte) 64)
                .setProtocol(IPv4.PROTOCOL_ICMP)
                .setSourceAddress(type == 0 ? ipPacket.getDestinationAddress() : ingressPort.getIpAddress())
                .setDestinationAddress(ipPacket.getSourceAddress())
                .setPayload(icmp);
/**
        Ethernet eth = (Ethernet) new Ethernet()
                .setEtherType(Ethernet.TYPE_IPv4)
                .setSourceMACAddress(ingressPort.getMacAddress().toBytes())
                .setDestinationMACAddress(inboundFrame.getSourceMACAddress())
                .setPayload(icmpIp);

        sendPacket(eth, ingressPort);
    }
**/
 
// Do a proper route lookup to find the path back to the sender
        RouteEntry icmpRoute = routeTable.lookup(icmpIp.getDestinationAddress());
        if (icmpRoute == null) return; // Drop if we literally have no route back

        Iface egressPort = icmpRoute.getInterface();
        int nextHop = icmpRoute.getGatewayAddress() == 0 ? icmpIp.getDestinationAddress() : icmpRoute.getGatewayAddress();
        ArpEntry nextHopMac = arpCache.lookup(nextHop);

        if (nextHopMac == null) {
                // If we don't know the MAC, drop it (standard behavior for ICMP generation)
                return;
        }

        Ethernet eth = (Ethernet) new Ethernet()
                .setEtherType(Ethernet.TYPE_IPv4)
                .setSourceMACAddress(egressPort.getMacAddress().toBytes())
                .setDestinationMACAddress(nextHopMac.getMac().toBytes()) // Route to proper next hop
                .setPayload(icmpIp);

        sendPacket(eth, egressPort);  

}
 private void routeIpv4Datagram(Ethernet inboundFrame, Iface ingressPort) {
        if (inboundFrame.getEtherType() != Ethernet.TYPE_IPv4) {
            return;
        }

        System.out.println("TOP route ipv4data");
        IPv4 ipv4Payload = (IPv4)inboundFrame.getPayload();
        System.out.println("Handle IP packet");

        // Save the original checksum first
        short oldChecksum = ipv4Payload.getChecksum();

        // Recompute checksum
        byte[] rawBytes = ipv4Payload.serialize();
        ipv4Payload.deserialize(rawBytes, 0, rawBytes.length);

        if (oldChecksum != ipv4Payload.getChecksum()) {
            System.out.println("DROP: Bad Checksum!");
            return;
        }
        System.out.println("Checksum good");


        System.out.println("Check TTL");
        ipv4Payload.setTtl((byte) (ipv4Payload.getTtl() - 1));
        if (ipv4Payload.getTtl() == 0) {
            System.out.println("ttl 0");
            dispatchIcmp(11, 0, inboundFrame, ingressPort);
            return;
        }

        ipv4Payload.resetChecksum();

        System.out.println("HandleRIP");
        if (ipv4Payload.getDestinationAddress() == MCAST_RIP_IP) {
            System.out.println("RIP RECEIVED");
            ripHandler.handleRipMessage(inboundFrame, ingressPort);
            return;
        }

        int destIp = ipv4Payload.getDestinationAddress();

        System.out.println("=== IPv4 PACKET DEBUG ===");
        System.out.println("Dest IP: " + IPv4.fromIPv4Address(destIp));
        System.out.println("Ingress Port: " + ingressPort.getName());

        boolean isForRouter = false;

        // Check all interfaces
        for (Iface iface : Router.this.interfaces.values()) {
            String ifaceIpStr = IPv4.fromIPv4Address(iface.getIpAddress());
            System.out.println("Checking interface " + iface.getName() + 
                            " with IP " + ifaceIpStr);
            if (ipv4Payload.getDestinationAddress() == iface.getIpAddress()) {
                switch (ipv4Payload.getProtocol()) {
					case IPv4.PROTOCOL_UDP:

                    UDP udpPayload = (UDP) ipv4Payload.getPayload();
                                
                                                if (udpPayload.getDestinationPort() == UDP.RIP_PORT) {
                                                        ripHandler.handleRipMessage(inboundFrame, ingressPort);

                                                        break;
                                                }
					case IPv4.PROTOCOL_TCP:
						dispatchIcmp(3, 3, inboundFrame, ingressPort);
						break;
					case IPv4.PROTOCOL_ICMP:
						ICMP icmp = (ICMP) ipv4Payload.getPayload();
						if (icmp.getIcmpType() == 8) {
							dispatchIcmp(0, 0, inboundFrame, ingressPort);
						}
						break;
				}
                System.out.println("Packet is for router but not handled (dropping or ICMP)");
                return;
            }
        }
        System.out.println("NOT for router, forwarding...");
        forwardIpPacket(inboundFrame, ingressPort);
    }

    // ==============================================================================
    // RIP Protocol Inner Class
    // ==============================================================================

    private class RipProtocolHandler {

        private Map<Integer, RipEntry> ripRouteRegistry = new HashMap<>();
        private static final int INF_METRIC = 16;
        private boolean logRipStatus = true;
        private Timer taskScheduler = new Timer(true);

        public void startRIP() {

            for (Iface port : Router.this.interfaces.values()) {
                System.out.println("Start");
                int subnetMask = port.getSubnetMask();
                int netAddress = subnetMask & port.getIpAddress();
                
                ripRouteRegistry.put(netAddress, new RipEntry(netAddress, subnetMask, 0, 0, -1));
                routeTable.insert(netAddress, 0, subnetMask, port);

                sendRipUpdate(REQ_RIP, null, port);
            }

            TimerTask periodicBroadcast = new TimerTask() {
                public void run() {
                    if (logRipStatus) System.out.println("Broadcasting periodic RIP response");
                    for (Iface port : interfaces.values()) {
                        sendRipUpdate(UNSOLICITED_RIP, null, port);
                    }
                }
            };

            TimerTask staleRouteCleaner = new TimerTask() {
                public void run() {
                    long currentTime = System.currentTimeMillis();
                    Iterator<Map.Entry<Integer, RipEntry>> iter = ripRouteRegistry.entrySet().iterator();
                    while (iter.hasNext()) {
                        RipEntry record = iter.next().getValue();
                        if (record.lastUpdated != -1 && (currentTime - record.lastUpdated) >= 30000) {
                            if (logRipStatus) System.out.println("Route timed out: " + IPv4.fromIPv4Address(record.networkAddr));
                            routeTable.remove(record.networkAddr, record.networkMask);
                            iter.remove();
                        }
                    }
                }
            };

            taskScheduler.schedule(periodicBroadcast, 0, 10000);
            taskScheduler.schedule(staleRouteCleaner, 0, 1000);
        }

        public void handleRipMessage(Ethernet inboundFrame, Iface ingressPort) {
            System.out.println("INSERT00");
            IPv4 ip = (IPv4)inboundFrame.getPayload();
            UDP udp = (UDP)ip.getPayload();
            RIPv2 rip = (RIPv2)udp.getPayload();

            byte ripCommand = rip.getCommand();
            switch (ripCommand) {
                case RIPv2.COMMAND_REQUEST:
                    System.out.println("INSERT0");
                    sendRipUpdate(RESP_RIP, inboundFrame, ingressPort);
                    break;

                case RIPv2.COMMAND_RESPONSE:
                    IPv4 ipv4Payload = (IPv4) inboundFrame.getPayload();
                    UDP udpDatagram = (UDP) ipv4Payload.getPayload();
                    RIPv2 ripMessage = (RIPv2) udpDatagram.getPayload();
                    System.out.println("INSERT1");

                    for (RIPv2Entry ripUpdate : ripMessage.getEntries()) {
                        int destNetwork = ripUpdate.getAddress() & ripUpdate.getSubnetMask();
                        int calculatedMetric = Math.min(ripUpdate.getMetric() + 1, INF_METRIC);
                        int neighborIp = ipv4Payload.getSourceAddress();
                        System.out.println("INSERT2");

                        synchronized (this.ripRouteRegistry) {
                            if (ripRouteRegistry.containsKey(destNetwork)) {
                                RipEntry currentRecord = ripRouteRegistry.get(destNetwork);
                                currentRecord.lastUpdated = System.currentTimeMillis();
                                System.out.println("INSERT3.5");

                                if (calculatedMetric < currentRecord.metricCount || currentRecord.hopGateway == neighborIp) {
                                    currentRecord.metricCount = calculatedMetric;
                                    currentRecord.hopGateway = neighborIp;
                                    System.out.println("INSERT3");

                            if (calculatedMetric < INF_METRIC) {
                                                                        System.out.println("INSERT5");
                                                                        // CHANGED: Use destNetwork instead of ripUpdate.getAddress()
                                                                        Router.this.routeTable.update(destNetwork, ripUpdate.getSubnetMask(), neighborIp, ingressPort);
                                                                    } else {
                                                                        System.out.println("INSERT6");
                                                                        // CHANGED: Use destNetwork instead of ripUpdate.getAddress()
                                                                        Router.this.routeTable.remove(destNetwork, ripUpdate.getSubnetMask());
                                                                    }
                                                                }
                                                        } else if (calculatedMetric < INF_METRIC) {
                                                                // CHANGED: Use destNetwork instead of ripUpdate.getAddress()
                                                                ripRouteRegistry.put(destNetwork, new RipEntry(destNetwork, ripUpdate.getSubnetMask(), neighborIp, calculatedMetric, System.currentTimeMillis()));
                                                                System.out.println("INSERT4");
                                                                Router.this.routeTable.insert(destNetwork, neighborIp, ripUpdate.getSubnetMask(), ingressPort);
                                                        }
                     }
                    }

                    break;
            }
        }

        private void sendRipUpdate(int mode, Ethernet requestingFrame, Iface egressPort) {
            Ethernet ethernetWrapper = new Ethernet();
            IPv4 ipHeader = new IPv4();
            UDP udpHeader = new UDP();
            RIPv2 ripMessage = new RIPv2();

            System.out.println("RIP UPDATE");
            ethernetWrapper.setSourceMACAddress(egressPort.getMacAddress().toBytes());
            ethernetWrapper.setEtherType(Ethernet.TYPE_IPv4);
            ipHeader.setTtl((byte) 64);
            ipHeader.setProtocol(IPv4.PROTOCOL_UDP);
            ipHeader.setSourceAddress(egressPort.getIpAddress());
            udpHeader.setSourcePort(UDP.RIP_PORT);
            udpHeader.setDestinationPort(UDP.RIP_PORT);

            switch (mode) {
                case UNSOLICITED_RIP:
                case REQ_RIP:
                     System.out.println("REQ");
                    ripMessage.setCommand(mode == REQ_RIP ? RIPv2.COMMAND_REQUEST : RIPv2.COMMAND_RESPONSE);
                    ethernetWrapper.setDestinationMACAddress(BCAST_MAC);
                    ipHeader.setDestinationAddress(MCAST_RIP_IP);
                    break;

                case RESP_RIP:
                    System.out.println("RESP");
                    IPv4 triggerIp = (IPv4) requestingFrame.getPayload();
                    ripMessage.setCommand(RIPv2.COMMAND_RESPONSE);
                    ethernetWrapper.setDestinationMACAddress(requestingFrame.getSourceMACAddress());
                    ipHeader.setDestinationAddress(triggerIp.getSourceAddress());
                    break;
            }

            List<RIPv2Entry> updateList = new ArrayList<>();
            synchronized (this.ripRouteRegistry) {
                for (RipEntry record : ripRouteRegistry.values()) {
                    updateList.add(new RIPv2Entry(record.networkAddr, record.networkMask, record.metricCount));
                }
            }

            System.out.println("curr error");
            ripMessage.setEntries(updateList);
            udpHeader.setPayload(ripMessage);
            ipHeader.setPayload(udpHeader);
            ethernetWrapper.setPayload(ipHeader);

            Router.this.sendPacket(ethernetWrapper, egressPort);
        }

        private class RipEntry {
            public int networkAddr;
            public int networkMask;
            public int hopGateway;
            public int metricCount;
            public long lastUpdated;

            public RipEntry(int networkAddr, int networkMask, int hopGateway, int metricCount, long lastUpdated) {
                this.networkAddr = networkAddr;
                this.networkMask = networkMask;
                this.hopGateway = hopGateway;
                this.metricCount = metricCount;
                this.lastUpdated = lastUpdated;
            }
        }
    }
}
