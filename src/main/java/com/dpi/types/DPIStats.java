package com.dpi.types;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Engine-wide statistics.
 * Mirrors C++ DPIStats from types.h.
 * Uses AtomicLong for lock-free updates from multiple FP threads.
 */
public class DPIStats {
    public final AtomicLong totalPackets       = new AtomicLong();
    public final AtomicLong totalBytes         = new AtomicLong();
    public final AtomicLong forwardedPackets   = new AtomicLong();
    public final AtomicLong droppedPackets     = new AtomicLong();
    public final AtomicLong tcpPackets         = new AtomicLong();
    public final AtomicLong udpPackets         = new AtomicLong();
    public final AtomicLong otherPackets       = new AtomicLong();
    public final AtomicLong activeConnections  = new AtomicLong();
}
