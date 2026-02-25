package com.dpi.pcap;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Reads PCAP files in both native and swapped byte order.
 * Mirrors the C++ PcapReader behaviour exactly.
 */
public class PcapReader implements Closeable {

    private static final int PCAP_MAGIC_NATIVE  = 0xa1b2c3d4;
    private static final int PCAP_MAGIC_SWAPPED = 0xd4c3b2a1;

    // ---- global header fields ----
    private int snaplen;
    private int network;
    private int versionMajor;
    private int versionMinor;
    private ByteOrder byteOrder = ByteOrder.BIG_ENDIAN;

    private DataInputStream in;
    private boolean open = false;

    /** Raw per-packet data returned by {@link #readNextPacket()}. */
    public static class RawPacket {
        public long tsSec;
        public long tsUsec;
        public int  inclLen;
        public int  origLen;
        public byte[] data;
    }

    public boolean open(String filename) throws IOException {
        File f = new File(filename);
        if (!f.exists()) {
            System.err.println("Error: File not found: " + filename);
            return false;
        }
        in = new DataInputStream(new BufferedInputStream(new FileInputStream(f)));

        // Read 24-byte global header using big-endian first
        ByteBuffer hdr = readBytes(24);
        hdr.order(ByteOrder.BIG_ENDIAN);
        int magic = hdr.getInt(0);

        if (magic == PCAP_MAGIC_NATIVE) {
            byteOrder = ByteOrder.BIG_ENDIAN;
        } else if (magic == Integer.reverseBytes(PCAP_MAGIC_SWAPPED) ||
                   Integer.reverseBytes(magic) == PCAP_MAGIC_NATIVE) {
            byteOrder = ByteOrder.LITTLE_ENDIAN;
        } else {
            // Try little-endian interpretation
            hdr.order(ByteOrder.LITTLE_ENDIAN);
            magic = hdr.getInt(0);
            if (magic == PCAP_MAGIC_NATIVE) {
                byteOrder = ByteOrder.LITTLE_ENDIAN;
            } else if (magic == PCAP_MAGIC_SWAPPED) {
                byteOrder = ByteOrder.BIG_ENDIAN;
            } else {
                System.err.printf("Error: Invalid PCAP magic number: 0x%08X%n", magic);
                return false;
            }
        }

        hdr.order(byteOrder);
        hdr.position(0);
        hdr.getInt(); // magic (consumed)
        versionMajor = hdr.getShort() & 0xFFFF;
        versionMinor = hdr.getShort() & 0xFFFF;
        hdr.getInt(); // thiszone
        hdr.getInt(); // sigfigs
        snaplen = hdr.getInt();
        network = hdr.getInt();

        System.out.println("Opened PCAP file: " + filename);
        System.out.printf("  Version: %d.%d%n", versionMajor, versionMinor);
        System.out.printf("  Snaplen: %d bytes%n", snaplen);
        System.out.printf("  Link type: %d%s%n", network, network == 1 ? " (Ethernet)" : "");

        open = true;
        return true;
    }

    /** Returns the next packet or null at EOF. */
    public RawPacket readNextPacket() throws IOException {
        if (!open) return null;

        // 16-byte packet header
        ByteBuffer phdr;
        try {
            phdr = readBytes(16);
        } catch (EOFException e) {
            return null;
        }
        phdr.order(byteOrder);

        RawPacket pkt = new RawPacket();
        pkt.tsSec  = phdr.getInt() & 0xFFFFFFFFL;
        pkt.tsUsec = phdr.getInt() & 0xFFFFFFFFL;
        pkt.inclLen = phdr.getInt();
        pkt.origLen = phdr.getInt();

        if (pkt.inclLen <= 0 || pkt.inclLen > 65535) {
            System.err.println("Error: Invalid packet length: " + pkt.inclLen);
            return null;
        }

        pkt.data = new byte[pkt.inclLen];
        int read = 0;
        while (read < pkt.inclLen) {
            int n = in.read(pkt.data, read, pkt.inclLen - read);
            if (n < 0) return null;
            read += n;
        }
        return pkt;
    }

    /** Write a minimal PCAP global header (little-endian, Ethernet) to an output stream. */
    public static void writeGlobalHeader(DataOutputStream out) throws IOException {
        ByteBuffer b = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        b.putInt(PCAP_MAGIC_NATIVE); // write as native; use little-endian
        b.putShort((short) 2);
        b.putShort((short) 4);
        b.putInt(0);
        b.putInt(0);
        b.putInt(65535);
        b.putInt(1); // Ethernet
        out.write(b.array());
    }

    /** Write one packet record to an output stream. */
    public static void writePacket(DataOutputStream out, RawPacket pkt) throws IOException {
        ByteBuffer b = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        b.putInt((int) pkt.tsSec);
        b.putInt((int) pkt.tsUsec);
        b.putInt(pkt.data.length);
        b.putInt(pkt.data.length);
        out.write(b.array());
        out.write(pkt.data);
    }

    @Override
    public void close() {
        if (in != null) {
            try { in.close(); } catch (IOException ignored) {}
        }
        open = false;
    }

    // ---- helpers ----

    private ByteBuffer readBytes(int n) throws IOException {
        byte[] buf = new byte[n];
        int read = 0;
        while (read < n) {
            int r = in.read(buf, read, n - read);
            if (r < 0) throw new EOFException();
            read += r;
        }
        return ByteBuffer.wrap(buf);
    }

    public int getNetwork() { return network; }
    public int getSnaplen() { return snaplen; }
}
