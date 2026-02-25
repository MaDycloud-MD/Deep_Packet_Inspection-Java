package com.dpi.parser;

import com.dpi.pcap.PcapReader;
import com.dpi.types.FiveTuple;
import com.dpi.types.PacketJob;

/**
 * Stateless packet parser.
 * Mirrors C++ PacketParser: Ethernet -> IPv4 -> TCP/UDP.
 * Captures all layer offsets so callers can reference any header inside data[].
 */
public class PacketParser {

    public static final int ETHERTYPE_IPV4 = 0x0800;
    public static final int PROTO_ICMP = 1;
    public static final int PROTO_TCP  = 6;
    public static final int PROTO_UDP  = 17;

    public static final int FLAG_FIN = 0x01;
    public static final int FLAG_SYN = 0x02;
    public static final int FLAG_RST = 0x04;
    public static final int FLAG_PSH = 0x08;
    public static final int FLAG_ACK = 0x10;
    public static final int FLAG_URG = 0x20;

    public static class ParseResult {
        public boolean valid;
        public boolean hasIp;
        public boolean hasTcp;
        public boolean hasUdp;

        public int  srcIp;
        public int  dstIp;
        public int  srcPort;
        public int  dstPort;
        public int  protocol;
        public int  tcpFlags;

        public int  ethOffset        = 0;
        public int  ipOffset         = 14;
        public int  transportOffset;
        public int  payloadOffset;
        public int  payloadLength;

        public long seqNumber;
        public long ackNumber;
        public int  ttl;
    }

    public static ParseResult parse(byte[] data) {
        ParseResult r = new ParseResult();
        if (data == null || data.length < 14) return r;

        int etherType = readUshort(data, 12);
        if (etherType != ETHERTYPE_IPV4) return r;

        int offset = 14;

        if (data.length < offset + 20) return r;
        int versionIhl = data[offset] & 0xFF;
        if (((versionIhl >> 4) & 0x0F) != 4) return r;

        int ihl = (versionIhl & 0x0F) * 4;
        if (ihl < 20 || data.length < offset + ihl) return r;

        r.ttl      = data[offset + 8] & 0xFF;
        r.protocol = data[offset + 9] & 0xFF;
        r.srcIp    = readInt(data, offset + 12);
        r.dstIp    = readInt(data, offset + 16);
        r.hasIp    = true;

        offset += ihl;
        r.transportOffset = offset;

        if (r.protocol == PROTO_TCP) {
            if (data.length < offset + 20) return r;
            r.srcPort   = readUshort(data, offset);
            r.dstPort   = readUshort(data, offset + 2);
            r.seqNumber = readUint(data, offset + 4);
            r.ackNumber = readUint(data, offset + 8);
            int tcpHdrLen = ((data[offset + 12] & 0xFF) >> 4) * 4;
            r.tcpFlags    = data[offset + 13] & 0xFF;
            if (tcpHdrLen < 20 || data.length < offset + tcpHdrLen) return r;
            offset  += tcpHdrLen;
            r.hasTcp = true;

        } else if (r.protocol == PROTO_UDP) {
            if (data.length < offset + 8) return r;
            r.srcPort = readUshort(data, offset);
            r.dstPort = readUshort(data, offset + 2);
            offset   += 8;
            r.hasUdp  = true;

        } else {
            return r;
        }

        r.payloadOffset = offset;
        r.payloadLength = data.length - offset;
        r.valid = true;
        return r;
    }

    public static PacketJob toJob(long id, PcapReader.RawPacket raw) {
        ParseResult r = parse(raw.data);
        if (!r.valid || !r.hasIp || (!r.hasTcp && !r.hasUdp)) return null;

        FiveTuple tuple = new FiveTuple(r.srcIp, r.dstIp, r.srcPort, r.dstPort, r.protocol);
        return new PacketJob(
                id, raw.tsSec, raw.tsUsec, tuple, raw.data,
                r.ethOffset, r.ipOffset, r.transportOffset,
                r.payloadOffset, r.payloadLength, r.tcpFlags);
    }

    public static String tcpFlagsToString(int flags) {
        StringBuilder sb = new StringBuilder();
        if ((flags & FLAG_SYN) != 0) sb.append("SYN ");
        if ((flags & FLAG_ACK) != 0) sb.append("ACK ");
        if ((flags & FLAG_FIN) != 0) sb.append("FIN ");
        if ((flags & FLAG_RST) != 0) sb.append("RST ");
        if ((flags & FLAG_PSH) != 0) sb.append("PSH ");
        if ((flags & FLAG_URG) != 0) sb.append("URG ");
        return sb.isEmpty() ? "none" : sb.toString().trim();
    }

    public static int readUshort(byte[] d, int off) {
        return ((d[off] & 0xFF) << 8) | (d[off + 1] & 0xFF);
    }

    public static int readInt(byte[] d, int off) {
        return ((d[off]   & 0xFF) << 24) | ((d[off+1] & 0xFF) << 16)
             | ((d[off+2] & 0xFF) <<  8) |  (d[off+3] & 0xFF);
    }

    public static long readUint(byte[] d, int off) {
        return readInt(d, off) & 0xFFFFFFFFL;
    }
}
