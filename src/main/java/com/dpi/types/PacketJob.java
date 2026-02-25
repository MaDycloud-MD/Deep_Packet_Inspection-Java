package com.dpi.types;

/**
 * Self-contained packet job passed between pipeline stages.
 * All data is copied so there are no shared-memory hazards.
 *
 * Mirrors the C++ PacketJob struct from types.h exactly:
 *   - ethOffset    : start of Ethernet header  (always 0)
 *   - ipOffset     : start of IP header         (always 14 for Ethernet)
 *   - transportOffset : start of TCP/UDP header
 *   - payloadOffset   : start of L7 application data
 *   - payloadLength   : bytes of L7 payload
 */
public class PacketJob {
    public final long       id;
    public final long       tsSec;
    public final long       tsUsec;
    public final FiveTuple  tuple;
    public final byte[]     data;           // full Ethernet frame bytes

    // Layer offsets into data[]
    public final int  ethOffset;            // always 0
    public final int  ipOffset;             // always 14
    public final int  transportOffset;      // start of TCP/UDP header
    public final int  payloadOffset;        // start of application payload
    public final int  payloadLength;        // bytes of application payload

    public final int  tcpFlags;             // TCP flag byte (0 if UDP)

    public PacketJob(long id, long tsSec, long tsUsec,
                     FiveTuple tuple, byte[] data,
                     int ethOffset, int ipOffset, int transportOffset,
                     int payloadOffset, int payloadLength,
                     int tcpFlags) {
        this.id               = id;
        this.tsSec            = tsSec;
        this.tsUsec           = tsUsec;
        this.tuple            = tuple;
        this.data             = data;
        this.ethOffset        = ethOffset;
        this.ipOffset         = ipOffset;
        this.transportOffset  = transportOffset;
        this.payloadOffset    = payloadOffset;
        this.payloadLength    = payloadLength;
        this.tcpFlags         = tcpFlags;
    }

    /** Convenience: get the payload slice as a new byte[] (allocates — use sparingly). */
    public byte[] copyPayload() {
        if (payloadLength <= 0 || payloadOffset + payloadLength > data.length) return new byte[0];
        byte[] out = new byte[payloadLength];
        System.arraycopy(data, payloadOffset, out, 0, payloadLength);
        return out;
    }
}
