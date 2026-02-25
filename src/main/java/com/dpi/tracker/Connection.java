package com.dpi.tracker;

import com.dpi.types.AppType;
import com.dpi.types.FiveTuple;
import com.dpi.types.PacketAction;

import java.time.Instant;

public class Connection {

    public enum State { NEW, ESTABLISHED, CLASSIFIED, BLOCKED, CLOSED }

    public final FiveTuple tuple;
    public volatile State       state       = State.NEW;
    public volatile AppType     appType     = AppType.UNKNOWN;
    public volatile String      sni         = "";
    public volatile PacketAction action     = PacketAction.FORWARD;

    // TCP handshake tracking
    public volatile boolean synSeen    = false;
    public volatile boolean synAckSeen = false;
    public volatile boolean finSeen    = false;

    // Stats
    public volatile long packetsIn  = 0;
    public volatile long packetsOut = 0;
    public volatile long bytesIn    = 0;
    public volatile long bytesOut   = 0;

    public final Instant firstSeen = Instant.now();
    public volatile Instant lastSeen = firstSeen;

    public Connection(FiveTuple tuple) {
        this.tuple = tuple;
    }
}
