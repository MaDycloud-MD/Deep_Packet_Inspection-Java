package com.dpi.types;

import java.util.Objects;

/**
 * Immutable five-tuple that uniquely identifies a network flow.
 * IPs are stored as unsigned 32-bit ints (Java int, interpreted unsigned).
 */
public final class FiveTuple {
    public final int srcIp;   // stored in host byte order
    public final int dstIp;
    public final int srcPort; // 0-65535
    public final int dstPort;
    public final int protocol; // 6=TCP, 17=UDP

    public FiveTuple(int srcIp, int dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.protocol = protocol;
    }

    public FiveTuple reverse() {
        return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof FiveTuple t)) return false;
        return srcIp == t.srcIp && dstIp == t.dstIp
                && srcPort == t.srcPort && dstPort == t.dstPort
                && protocol == t.protocol;
    }

    @Override
    public int hashCode() {
        // Multiplicative hash for good distribution
        int h = srcIp;
        h = h * 31 + dstIp;
        h = h * 31 + srcPort;
        h = h * 31 + dstPort;
        h = h * 31 + protocol;
        return h;
    }

    public static String ipToString(int ip) {
        return ((ip) & 0xFF) + "." +
               ((ip >> 8) & 0xFF) + "." +
               ((ip >> 16) & 0xFF) + "." +
               ((ip >> 24) & 0xFF);
    }

    public static int parseIp(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) throw new IllegalArgumentException("Invalid IP: " + ip);
        int result = 0;
        for (int i = 3; i >= 0; i--) {
            result = (result << 8) | Integer.parseInt(parts[i]);
        }
        return result;
    }

    @Override
    public String toString() {
        String proto = protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?";
        return ipToString(srcIp) + ":" + srcPort + " -> " +
               ipToString(dstIp) + ":" + dstPort + " (" + proto + ")";
    }
}
