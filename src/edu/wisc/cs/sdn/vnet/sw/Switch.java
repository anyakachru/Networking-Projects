package edu.wisc.cs.sdn.vnet.sw;

import net.floodlightcontroller.packet.Ethernet;
import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.lang.Runnable;
import java.lang.Thread;



/**
 * @author Aaron Gember-Jacobson
 */
public class Switch extends Device
{	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */

        private Map<Long, MacTableEntry> macTable;
	public Switch(String host, DumpFile logfile)
	{
		super(host,logfile);
                this.macTable = new HashMap<Long, MacTableEntry>();
	}


    // Remove MAC entries older than 15 seconds
    private void cleanupMacTable() {
        long now = System.currentTimeMillis();
        long timeout = 15 * 1000; // 15 sec

        macTable.entrySet().removeIf(
            e -> (now - e.getValue().lastSeen) > timeout
        );
    }

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
				etherPacket.toString().replace("\n", "\n\t"));

        cleanupMacTable();

        long srcMac = Ethernet.toLong(etherPacket.getSourceMACAddress());
        long dstMac = Ethernet.toLong(etherPacket.getDestinationMACAddress());
        long now = System.currentTimeMillis();

        // Learn/update the source MAc
        macTable.put(srcMac, new MacTableEntry(inIface, now));

        //Check if we already know the outbound interface for the destination
        MacTableEntry destEntry = macTable.get(dstMac);

        if (destEntry != null) {
            // Known destination: forward unicast

            // Don’t send it back out the same interface
            if (destEntry.iface == inIface) {
                return;
            }

            this.sendPacket(etherPacket, destEntry.iface);
        }
        else {
            // Unknown destination: flood the packet
            for (Iface outIface : this.interfaces.values()) {
                if (outIface != inIface) {
                    this.sendPacket(etherPacket, outIface);
                }
            }
        }

	}//end method
}//end class
