package com.dpi.sni;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Layer-7 protocol extractors: TLS SNI, HTTP Host header, DNS query.
 * All methods are stateless and take raw payload bytes.
 */
public class SNIExtractor {

    // TLS constants
    private static final int CONTENT_TYPE_HANDSHAKE = 0x16;
    private static final int HANDSHAKE_CLIENT_HELLO = 0x01;
    private static final int EXTENSION_SNI          = 0x0000;
    private static final int SNI_TYPE_HOSTNAME       = 0x00;

    // -----------------------------------------------------------------------
    // TLS SNI
    // -----------------------------------------------------------------------

    public static Optional<String> extractTlsSni(byte[] data, int offset, int length) {
        if (length < 9 || offset + length > data.length) return Optional.empty();

        // Content type = 0x16 (Handshake)
        if ((data[offset] & 0xFF) != CONTENT_TYPE_HANDSHAKE) return Optional.empty();

        // TLS version check (0x0300 – 0x0304)
        int ver = readU16(data, offset + 1);
        if (ver < 0x0300 || ver > 0x0304) return Optional.empty();

        // Record length
        int recLen = readU16(data, offset + 3);
        if (recLen > length - 5) return Optional.empty();

        // Handshake type
        if ((data[offset + 5] & 0xFF) != HANDSHAKE_CLIENT_HELLO) return Optional.empty();

        int pos = offset + 5;   // start of Handshake header

        // Skip: handshake type (1) + length (3) + client version (2) + random (32)
        pos += 1 + 3 + 2 + 32;
        if (pos >= offset + length) return Optional.empty();

        // Session ID
        int sidLen = data[pos] & 0xFF;
        pos += 1 + sidLen;

        // Cipher suites
        if (pos + 2 > offset + length) return Optional.empty();
        int csLen = readU16(data, pos);
        pos += 2 + csLen;

        // Compression methods
        if (pos >= offset + length) return Optional.empty();
        int compLen = data[pos] & 0xFF;
        pos += 1 + compLen;

        // Extensions
        if (pos + 2 > offset + length) return Optional.empty();
        int extTotalLen = readU16(data, pos);
        pos += 2;
        int extEnd = Math.min(pos + extTotalLen, offset + length);

        while (pos + 4 <= extEnd) {
            int extType = readU16(data, pos);
            int extLen  = readU16(data, pos + 2);
            pos += 4;

            if (pos + extLen > extEnd) break;

            if (extType == EXTENSION_SNI && extLen >= 5) {
                // SNI list length (2) + type (1) + name length (2) + name
                int sniType   = data[pos + 2] & 0xFF;
                int sniLen    = readU16(data, pos + 3);
                if (sniType == SNI_TYPE_HOSTNAME && sniLen > 0 && pos + 5 + sniLen <= extEnd) {
                    return Optional.of(new String(data, pos + 5, sniLen, StandardCharsets.US_ASCII));
                }
            }
            pos += extLen;
        }

        return Optional.empty();
    }

    // -----------------------------------------------------------------------
    // HTTP Host header
    // -----------------------------------------------------------------------

    public static Optional<String> extractHttpHost(byte[] data, int offset, int length) {
        if (length < 4 || offset + length > data.length) return Optional.empty();

        // Must start with an HTTP method
        String head = new String(data, offset, Math.min(length, 8), StandardCharsets.US_ASCII);
        if (!head.startsWith("GET ") && !head.startsWith("POST") && !head.startsWith("PUT ")
                && !head.startsWith("HEAD") && !head.startsWith("DELE")
                && !head.startsWith("PATC") && !head.startsWith("OPTI")) {
            return Optional.empty();
        }

        String payload = new String(data, offset, length, StandardCharsets.ISO_8859_1);
        String lower   = payload.toLowerCase();

        int hostIdx = lower.indexOf("\nhost:");
        if (hostIdx < 0) {
            hostIdx = lower.indexOf("\r\nhost:");
        }
        if (hostIdx < 0) return Optional.empty();

        int colon = payload.indexOf(':', hostIdx + 1);
        if (colon < 0) return Optional.empty();

        int start = colon + 1;
        while (start < payload.length() && (payload.charAt(start) == ' ' || payload.charAt(start) == '\t')) {
            start++;
        }

        int end = start;
        while (end < payload.length() && payload.charAt(end) != '\r' && payload.charAt(end) != '\n') {
            end++;
        }

        if (end <= start) return Optional.empty();

        String host = payload.substring(start, end).trim();
        // Strip port if present
        int portColon = host.indexOf(':');
        if (portColon >= 0) host = host.substring(0, portColon);

        return host.isEmpty() ? Optional.empty() : Optional.of(host);
    }

    // -----------------------------------------------------------------------
    // DNS query domain
    // -----------------------------------------------------------------------

    public static Optional<String> extractDnsQuery(byte[] data, int offset, int length) {
        if (length < 12 || offset + length > data.length) return Optional.empty();

        // QR bit must be 0 (query), QDCOUNT > 0
        if ((data[offset + 2] & 0x80) != 0) return Optional.empty();  // response
        int qdCount = readU16(data, offset + 4);
        if (qdCount == 0) return Optional.empty();

        int pos = offset + 12;
        StringBuilder domain = new StringBuilder();

        while (pos < offset + length) {
            int labelLen = data[pos] & 0xFF;
            if (labelLen == 0) break;
            if ((labelLen & 0xC0) == 0xC0) break; // compression pointer

            pos++;
            if (pos + labelLen > offset + length) break;

            if (domain.length() > 0) domain.append('.');
            domain.append(new String(data, pos, labelLen, StandardCharsets.US_ASCII));
            pos += labelLen;
        }

        return domain.length() == 0 ? Optional.empty() : Optional.of(domain.toString());
    }

    // -----------------------------------------------------------------------
    // Helper
    // -----------------------------------------------------------------------

    private static int readU16(byte[] d, int off) {
        return ((d[off] & 0xFF) << 8) | (d[off + 1] & 0xFF);
    }
}
