package com.dpi.tools;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Random;

/**
 * Generates a test PCAP file with various protocol traffic for DPI testing.
 *
 * Direct port of generate_test_pcap.py — produces identical packet structure:
 *   - TLS Client Hello packets with SNI for 16 popular services
 *   - HTTP GET requests with Host headers
 *   - DNS queries
 *   - TCP SYN/ACK handshakes
 *   - Traffic from a "blocked" source IP (192.168.1.50)
 *
 * Usage:
 *   java -cp dpi-engine.jar com.dpi.tools.GenerateTestPcap [output.pcap]
 *   (default output: test_dpi.pcap)
 */
public class GenerateTestPcap {

    private static final Random RNG = new Random(42); // fixed seed for reproducibility

    // ---- PCAP writers ----

    private final DataOutputStream out;
    private long timestamp = 1_700_000_000L;

    public GenerateTestPcap(String filename) throws IOException {
        out = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(filename)));
        writeGlobalHeader();
    }

    private void writeGlobalHeader() throws IOException {
        ByteBuffer b = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        b.putInt(0xa1b2c3d4);  // magic
        b.putShort((short) 2); // version major
        b.putShort((short) 4); // version minor
        b.putInt(0);           // thiszone
        b.putInt(0);           // sigfigs
        b.putInt(65535);       // snaplen
        b.putInt(1);           // linktype Ethernet
        out.write(b.array());
    }

    private void writePacket(byte[] data) throws IOException {
        long tsSec  = timestamp++;
        long tsUsec = RNG.nextInt(1_000_000) & 0xFFFFFFFFL;

        ByteBuffer b = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        b.putInt((int) tsSec);
        b.putInt((int) tsUsec);
        b.putInt(data.length);
        b.putInt(data.length);
        out.write(b.array());
        out.write(data);
    }

    public void close() throws IOException { out.close(); }

    // ---- frame builders ----

    /** 14-byte Ethernet header, EtherType 0x0800 (IPv4). */
    static byte[] ethernet(String srcMac, String dstMac) {
        byte[] f = new byte[14];
        byte[] sm = parseMac(srcMac), dm = parseMac(dstMac);
        System.arraycopy(dm, 0, f, 0, 6);
        System.arraycopy(sm, 0, f, 6, 6);
        f[12] = 0x08; f[13] = 0x00;
        return f;
    }

    /** 20-byte IPv4 header (no options). */
    static byte[] ipv4(String srcIp, String dstIp, int protocol, int payloadLen) {
        ByteBuffer b = ByteBuffer.allocate(20).order(ByteOrder.BIG_ENDIAN);
        b.put((byte) 0x45);                      // version=4, IHL=5
        b.put((byte) 0);                         // DSCP/ECN
        b.putShort((short)(20 + payloadLen));    // total length
        b.putShort((short)(RNG.nextInt(65535))); // identification
        b.putShort((short) 0x4000);              // don't-fragment
        b.put((byte) 64);                        // TTL
        b.put((byte) protocol);
        b.putShort((short) 0);                   // checksum (0 = unchecked)
        for (int x : parseIp(srcIp)) b.put((byte) x);
        for (int x : parseIp(dstIp)) b.put((byte) x);
        return b.array();
    }

    /** 20-byte TCP header (no options). */
    static byte[] tcp(int srcPort, int dstPort, int seq, int ack, int flags) {
        ByteBuffer b = ByteBuffer.allocate(20).order(ByteOrder.BIG_ENDIAN);
        b.putShort((short) srcPort);
        b.putShort((short) dstPort);
        b.putInt(seq);
        b.putInt(ack);
        b.put((byte)(5 << 4));  // data offset = 5 (20 bytes), reserved = 0
        b.put((byte) flags);
        b.putShort((short) 65535); // window
        b.putShort((short) 0);     // checksum
        b.putShort((short) 0);     // urgent pointer
        return b.array();
    }

    /** 8-byte UDP header. */
    static byte[] udp(int srcPort, int dstPort, int payloadLen) {
        ByteBuffer b = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN);
        b.putShort((short) srcPort);
        b.putShort((short) dstPort);
        b.putShort((short)(8 + payloadLen));
        b.putShort((short) 0); // checksum
        return b.array();
    }

    // ---- TLS Client Hello with SNI ----

    static byte[] tlsClientHello(String sni) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        // --- SNI extension (type 0x0000) ---
        byte[] sniBytes = sni.getBytes("US-ASCII");
        // SNI entry: type(1) + length(2) + value
        byte[] sniEntry = concat(new byte[]{0x00},
                                 u16be(sniBytes.length), sniBytes);
        // SNI list: list_length(2) + entries
        byte[] sniList = concat(u16be(sniEntry.length), sniEntry);
        // Extension: type(2) + ext_length(2) + data
        byte[] sniExt  = concat(u16be(0x0000), u16be(sniList.length), sniList);

        // --- Supported Versions extension (0x002b) for TLS 1.3 ---
        byte[] svExt = concat(u16be(0x002b), u16be(3),
                              new byte[]{0x02}, u16be(0x0304));

        byte[] extensions = concat(sniExt, svExt);
        byte[] extBlock   = concat(u16be(extensions.length), extensions);

        // --- Client Hello body ---
        byte[] random = new byte[32];
        RNG.nextBytes(random);
        byte[] cipherSuites = concat(u16be(4), u16be(0x1301), u16be(0x1302));
        byte[] compression  = new byte[]{0x01, 0x00};
        byte[] body = concat(u16be(0x0303), random,
                             new byte[]{0x00},  // session ID length = 0
                             cipherSuites, compression, extBlock);

        // --- Handshake header: type(1) + length(3) ---
        byte[] handshake = concat(new byte[]{0x01},
                                  u24be(body.length), body);

        // --- TLS record: content_type(1) + version(2) + length(2) + handshake ---
        return concat(new byte[]{0x16}, u16be(0x0301),
                      u16be(handshake.length), handshake);
    }

    // ---- HTTP request ----

    static byte[] httpRequest(String host, String path) {
        String req = "GET " + path + " HTTP/1.1\r\n"
                   + "Host: " + host + "\r\n"
                   + "User-Agent: DPI-Test/1.0\r\n"
                   + "Accept: */*\r\n\r\n";
        try { return req.getBytes("US-ASCII"); }
        catch (Exception e) { return req.getBytes(); }
    }

    // ---- DNS query ----

    static byte[] dnsQuery(String domain) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        // Transaction ID
        buf.write(u16be(RNG.nextInt(65535)));
        // Flags: standard query, recursion desired
        buf.write(u16be(0x0100));
        // QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        buf.write(u16be(1)); buf.write(u16be(0)); buf.write(u16be(0)); buf.write(u16be(0));
        // Question: QNAME
        for (String label : domain.split("\\.")) {
            buf.write((byte) label.length());
            buf.write(label.getBytes("US-ASCII"));
        }
        buf.write(0x00);         // null terminator
        buf.write(u16be(0x0001)); // QTYPE = A
        buf.write(u16be(0x0001)); // QCLASS = IN
        return buf.toByteArray();
    }

    // ---- helper: frame concatenation ----

    static byte[] concat(byte[]... parts) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        for (byte[] p : parts) b.write(p);
        return b.toByteArray();
    }

    static byte[] u16be(int v) {
        return new byte[]{(byte)(v >> 8), (byte) v};
    }

    static byte[] u24be(int v) {
        return new byte[]{(byte)(v >> 16), (byte)(v >> 8), (byte) v};
    }

    static byte[] parseMac(String mac) {
        String[] parts = mac.split(":");
        byte[] b = new byte[6];
        for (int i = 0; i < 6; i++) b[i] = (byte) Integer.parseInt(parts[i], 16);
        return b;
    }

    static int[] parseIp(String ip) {
        String[] p = ip.split("\\.");
        return new int[]{Integer.parseInt(p[0]), Integer.parseInt(p[1]),
                         Integer.parseInt(p[2]), Integer.parseInt(p[3])};
    }

    // ---- main logic ----

    public static void main(String[] args) throws Exception {
        String outputFile = args.length > 0 ? args[0] : "test_dpi.pcap";

        GenerateTestPcap w = new GenerateTestPcap(outputFile);

        final String USER_MAC    = "00:11:22:33:44:55";
        final String GATEWAY_MAC = "aa:bb:cc:dd:ee:ff";
        final String USER_IP     = "192.168.1.100";

        // ---- TLS connections with SNI ----
        String[][] tlsConns = {
            {"142.250.185.206", "www.google.com",      "443"},
            {"142.250.185.110", "www.youtube.com",     "443"},
            {"157.240.1.35",    "www.facebook.com",    "443"},
            {"157.240.1.174",   "www.instagram.com",   "443"},
            {"104.244.42.65",   "twitter.com",         "443"},
            {"52.94.236.248",   "www.amazon.com",      "443"},
            {"23.52.167.61",    "www.netflix.com",     "443"},
            {"140.82.114.4",    "github.com",          "443"},
            {"104.16.85.20",    "discord.com",         "443"},
            {"35.186.224.25",   "zoom.us",             "443"},
            {"35.186.227.140",  "web.telegram.org",    "443"},
            {"99.86.0.100",     "www.tiktok.com",      "443"},
            {"35.186.224.47",   "open.spotify.com",    "443"},
            {"192.0.78.24",     "www.cloudflare.com",  "443"},
            {"13.107.42.14",    "www.microsoft.com",   "443"},
            {"17.253.144.10",   "www.apple.com",       "443"},
        };

        int seqBase = 1000;
        for (String[] conn : tlsConns) {
            String dstIp  = conn[0];
            String sni    = conn[1];
            int dstPort   = Integer.parseInt(conn[2]);
            int srcPort   = 49152 + RNG.nextInt(16383);

            byte[] ethOut = ethernet(USER_MAC, GATEWAY_MAC);
            byte[] ethIn  = ethernet(GATEWAY_MAC, USER_MAC);

            // SYN
            byte[] tcpSyn = tcp(srcPort, dstPort, seqBase, 0, 0x02);
            byte[] ipSyn  = ipv4(USER_IP, dstIp, 6, tcpSyn.length);
            w.writePacket(concat(ethOut, ipSyn, tcpSyn));

            // SYN-ACK
            byte[] tcpSa  = tcp(dstPort, srcPort, seqBase + 1000, seqBase + 1, 0x12);
            byte[] ipSa   = ipv4(dstIp, USER_IP, 6, tcpSa.length);
            w.writePacket(concat(ethIn, ipSa, tcpSa));

            // ACK
            byte[] tcpAck = tcp(srcPort, dstPort, seqBase + 1, seqBase + 1001, 0x10);
            byte[] ipAck  = ipv4(USER_IP, dstIp, 6, tcpAck.length);
            w.writePacket(concat(ethOut, ipAck, tcpAck));

            // TLS Client Hello (PSH+ACK)
            byte[] tls     = tlsClientHello(sni);
            byte[] tcpTls  = tcp(srcPort, dstPort, seqBase + 1, seqBase + 1001, 0x18);
            byte[] ipTls   = ipv4(USER_IP, dstIp, 6, tcpTls.length + tls.length);
            w.writePacket(concat(ethOut, ipTls, tcpTls, tls));

            seqBase += 10_000;
        }

        // ---- HTTP connections ----
        String[][] httpConns = {
            {"93.184.216.34",    "example.com", "80"},
            {"185.199.108.153",  "httpbin.org", "80"},
        };

        for (String[] conn : httpConns) {
            String dstIp = conn[0];
            String host  = conn[1];
            int dstPort  = Integer.parseInt(conn[2]);
            int srcPort  = 49152 + RNG.nextInt(16383);

            byte[] ethOut = ethernet(USER_MAC, GATEWAY_MAC);

            // SYN
            byte[] tcpSyn = tcp(srcPort, dstPort, seqBase, 0, 0x02);
            byte[] ipSyn  = ipv4(USER_IP, dstIp, 6, tcpSyn.length);
            w.writePacket(concat(ethOut, ipSyn, tcpSyn));

            // HTTP GET (PSH+ACK)
            byte[] http   = httpRequest(host, "/");
            byte[] tcpHttp = tcp(srcPort, dstPort, seqBase + 1, 1, 0x18);
            byte[] ipHttp  = ipv4(USER_IP, dstIp, 6, tcpHttp.length + http.length);
            w.writePacket(concat(ethOut, ipHttp, tcpHttp, http));

            seqBase += 10_000;
        }

        // ---- DNS queries ----
        String[] dnsQueries = {
            "www.google.com", "www.youtube.com", "www.facebook.com", "api.twitter.com"
        };
        String DNS_SERVER = "8.8.8.8";

        for (String domain : dnsQueries) {
            int srcPort = 49152 + RNG.nextInt(16383);
            byte[] dns  = dnsQuery(domain);
            byte[] udpH = udp(srcPort, 53, dns.length);
            byte[] ip   = ipv4(USER_IP, DNS_SERVER, 17, udpH.length + dns.length);
            byte[] eth  = ethernet(USER_MAC, GATEWAY_MAC);
            w.writePacket(concat(eth, ip, udpH, dns));
        }

        // ---- Packets from "blocked" source IP ----
        String BLOCKED_IP    = "192.168.1.50";
        String BLOCKED_MAC   = "00:11:22:33:44:56";
        String DST_IP        = "172.217.0.100";

        for (int i = 0; i < 5; i++) {
            int srcPort  = 49152 + RNG.nextInt(16383);
            byte[] tcpSyn = tcp(srcPort, 443, seqBase, 0, 0x02);
            byte[] ip     = ipv4(BLOCKED_IP, DST_IP, 6, tcpSyn.length);
            byte[] eth    = ethernet(BLOCKED_MAC, GATEWAY_MAC);
            w.writePacket(concat(eth, ip, tcpSyn));
            seqBase += 1000;
        }

        w.close();

        System.out.println("Created " + outputFile + " with test traffic:");
        System.out.println("  - " + tlsConns.length + " TLS connections with SNI");
        System.out.println("  - " + httpConns.length + " HTTP connections");
        System.out.println("  - " + dnsQueries.length + " DNS queries");
        System.out.println("  - 5 packets from blocked IP " + BLOCKED_IP);
    }
}
