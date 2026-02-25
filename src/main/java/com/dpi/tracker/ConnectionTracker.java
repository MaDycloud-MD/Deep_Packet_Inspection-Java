package com.dpi.tracker;

import com.dpi.types.AppType;
import com.dpi.types.FiveTuple;
import com.dpi.types.PacketAction;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.function.Consumer;

/**
 * Per-FastPath connection tracker (NOT thread-safe — each FP owns one instance
 * and only its own thread reads/writes it).
 */
public class ConnectionTracker {

    private final int fpId;
    private final int maxConnections;
    private final LinkedHashMap<FiveTuple, Connection> table;

    private long totalSeen       = 0;
    private long classifiedCount = 0;
    private long blockedCount    = 0;

    public ConnectionTracker(int fpId, int maxConnections) {
        this.fpId = fpId;
        this.maxConnections = maxConnections;
        // Access-order LRU so eviction is O(1)
        this.table = new LinkedHashMap<>(1024, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<FiveTuple, Connection> eldest) {
                return size() > maxConnections;
            }
        };
    }

    public ConnectionTracker(int fpId) {
        this(fpId, 100_000);
    }

    // ---- lookup / creation ----

    public Connection getOrCreate(FiveTuple tuple) {
        Connection c = table.get(tuple);
        if (c == null) {
            c = table.get(tuple.reverse());
        }
        if (c == null) {
            c = new Connection(tuple);
            table.put(tuple, c);
            totalSeen++;
        }
        return c;
    }

    public Connection get(FiveTuple tuple) {
        Connection c = table.get(tuple);
        if (c == null) c = table.get(tuple.reverse());
        return c;
    }

    // ---- updates ----

    public void update(Connection conn, int packetSize, boolean outbound) {
        if (conn == null) return;
        conn.lastSeen = Instant.now();
        if (outbound) { conn.packetsOut++; conn.bytesOut += packetSize; }
        else          { conn.packetsIn++;  conn.bytesIn  += packetSize; }
    }

    public void classify(Connection conn, AppType app, String sni) {
        if (conn == null || conn.state == Connection.State.CLASSIFIED) return;
        conn.appType = app;
        conn.sni     = sni != null ? sni : "";
        conn.state   = Connection.State.CLASSIFIED;
        classifiedCount++;
    }

    public void block(Connection conn) {
        if (conn == null) return;
        conn.state  = Connection.State.BLOCKED;
        conn.action = PacketAction.DROP;
        blockedCount++;
    }

    public void updateTcpState(Connection conn, int flags) {
        if (conn == null) return;
        final int SYN = 0x02, ACK = 0x10, FIN = 0x01, RST = 0x04;

        if ((flags & SYN) != 0) {
            if ((flags & ACK) != 0) conn.synAckSeen = true;
            else conn.synSeen = true;
        }
        if (conn.synSeen && conn.synAckSeen && (flags & ACK) != 0) {
            if (conn.state == Connection.State.NEW) conn.state = Connection.State.ESTABLISHED;
        }
        if ((flags & FIN) != 0) conn.finSeen = true;
        if ((flags & RST) != 0) conn.state = Connection.State.CLOSED;
        if (conn.finSeen && (flags & ACK) != 0) conn.state = Connection.State.CLOSED;
    }

    // ---- maintenance ----

    public int cleanupStale(Duration timeout) {
        int removed = 0;
        Instant cutoff = Instant.now().minus(timeout);
        Iterator<Map.Entry<FiveTuple, Connection>> it = table.entrySet().iterator();
        while (it.hasNext()) {
            Connection c = it.next().getValue();
            if (c.lastSeen.isBefore(cutoff) || c.state == Connection.State.CLOSED) {
                it.remove();
                removed++;
            }
        }
        return removed;
    }

    // ---- stats / iteration ----

    public int getActiveCount() { return table.size(); }

    public void forEach(Consumer<Connection> fn) {
        table.values().forEach(fn);
    }

    public record Stats(int active, long totalSeen, long classified, long blocked) {}

    public Stats getStats() {
        return new Stats(table.size(), totalSeen, classifiedCount, blockedCount);
    }
}
