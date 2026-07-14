package edu.wisc.cs.sdn.vnet.sw;

import edu.wisc.cs.sdn.vnet.Iface;

public class MacTableEntry {
    public Iface iface;
    public long lastSeen;

    public MacTableEntry(Iface iface, long lastSeen) {
        this.iface = iface;
        this.lastSeen = lastSeen;
    }
}
