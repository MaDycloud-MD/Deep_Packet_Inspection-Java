package com.dpi.fastpath;

import com.dpi.rules.RuleManager;
import com.dpi.sni.SNIExtractor;
import com.dpi.tracker.Connection;
import com.dpi.tracker.ConnectionTracker;
import com.dpi.types.AppType;
import com.dpi.types.PacketAction;
import com.dpi.types.PacketJob;

import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BiConsumer;

public class FastPathProcessor implements Runnable {

    private final int fpId;
    public final ThreadSafeQueue<PacketJob> inputQueue;
    private final ConnectionTracker connTracker;
    private final RuleManager ruleManager;
    private final BiConsumer<PacketJob, PacketAction> outputCallback;

    private Thread thread;
    private volatile boolean running = false;

    private final AtomicLong processed          = new AtomicLong();
    private final AtomicLong forwarded          = new AtomicLong();
    private final AtomicLong dropped            = new AtomicLong();
    private final AtomicLong sniExtractions     = new AtomicLong();
    private final AtomicLong classificationHits = new AtomicLong();

    public FastPathProcessor(int fpId, RuleManager ruleManager,
                              BiConsumer<PacketJob, PacketAction> outputCallback) {
        this.fpId           = fpId;
        this.ruleManager    = ruleManager;
        this.outputCallback = outputCallback;
        this.inputQueue     = new ThreadSafeQueue<>(10_000);
        this.connTracker    = new ConnectionTracker(fpId);
    }

    // ---- lifecycle ----

    public void start() {
        if (running) return;
        running = true;
        thread  = new Thread(this, "FP-" + fpId);
        thread.setDaemon(true);
        thread.start();
        System.out.println("[FP" + fpId + "] Started");
    }

    public void stop() {
        if (!running) return;
        running = false;
        inputQueue.shutdown();
        if (thread != null) {
            try { thread.join(3000); }
            catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        }
        System.out.printf("[FP%d] Stopped (processed %d packets)%n", fpId, processed.get());
    }

    @Override
    public void run() {
        long cleanupTimer = System.currentTimeMillis();

        while (running) {
            Optional<PacketJob> jobOpt = inputQueue.popWithTimeout(100);

            if (jobOpt.isEmpty()) {
                if (System.currentTimeMillis() - cleanupTimer > 30_000) {
                    connTracker.cleanupStale(Duration.ofSeconds(300));
                    cleanupTimer = System.currentTimeMillis();
                }
                continue;
            }

            processed.incrementAndGet();
            PacketJob job    = jobOpt.get();
            PacketAction action = processPacket(job);

            if (outputCallback != null) outputCallback.accept(job, action);

            if (action == PacketAction.DROP) dropped.incrementAndGet();
            else                             forwarded.incrementAndGet();
        }
    }

    // ---- core processing (mirrors FastPathProcessor::processPacket) ----

    private PacketAction processPacket(PacketJob job) {
        Connection conn = connTracker.getOrCreate(job.tuple);
        connTracker.update(conn, job.data.length, true);

        if (job.tuple.protocol == 6) { // TCP
            connTracker.updateTcpState(conn, job.tcpFlags);
        }

        if (conn.state == Connection.State.BLOCKED) return PacketAction.DROP;

        if (conn.state != Connection.State.CLASSIFIED && job.payloadLength > 0) {
            inspectPayload(job, conn);
        }

        return checkRules(job, conn);
    }

    private void inspectPayload(PacketJob job, Connection conn) {
        if (job.payloadOffset >= job.data.length || job.payloadLength == 0) return;

        // TLS SNI — port 443 or payload large enough to try
        if (job.tuple.dstPort == 443 || job.payloadLength >= 50) {
            Optional<String> sni = SNIExtractor.extractTlsSni(
                    job.data, job.payloadOffset, job.payloadLength);
            if (sni.isPresent()) {
                sniExtractions.incrementAndGet();
                AppType app = AppType.fromSni(sni.get());
                connTracker.classify(conn, app, sni.get());
                if (app != AppType.UNKNOWN && app != AppType.HTTPS) classificationHits.incrementAndGet();
                return;
            }
        }

        // HTTP Host header — port 80
        if (job.tuple.dstPort == 80) {
            Optional<String> host = SNIExtractor.extractHttpHost(
                    job.data, job.payloadOffset, job.payloadLength);
            if (host.isPresent()) {
                AppType app = AppType.fromSni(host.get());
                connTracker.classify(conn, app, host.get());
                if (app != AppType.UNKNOWN && app != AppType.HTTP) classificationHits.incrementAndGet();
                return;
            }
        }

        // DNS — port 53 (UDP or TCP)
        if (job.tuple.dstPort == 53 || job.tuple.srcPort == 53) {
            Optional<String> domain = SNIExtractor.extractDnsQuery(
                    job.data, job.payloadOffset, job.payloadLength);
            if (domain.isPresent()) {
                connTracker.classify(conn, AppType.DNS, domain.get());
                return;
            }
        }

        // Port-based fallback classification
        if      (job.tuple.dstPort == 443) connTracker.classify(conn, AppType.HTTPS, "");
        else if (job.tuple.dstPort == 80)  connTracker.classify(conn, AppType.HTTP,  "");
    }

    private PacketAction checkRules(PacketJob job, Connection conn) {
        if (ruleManager == null) return PacketAction.FORWARD;

        Optional<RuleManager.BlockReason> reason =
                ruleManager.shouldBlock(job.tuple.srcIp, job.tuple.dstPort,
                                        conn.appType, conn.sni);
        if (reason.isPresent()) {
            System.out.printf("[FP%d] BLOCKED packet: %s %s%n",
                    fpId, reason.get().type(), reason.get().detail());
            connTracker.block(conn);
            return PacketAction.DROP;
        }
        return PacketAction.FORWARD;
    }

    // ---- accessors ----

    public ConnectionTracker getConnectionTracker() { return connTracker; }
    public int getId()                              { return fpId; }

    public record Stats(long processed, long forwarded, long dropped,
                        int connections, long sniExtractions, long classificationHits) {}

    public Stats getStats() {
        return new Stats(processed.get(), forwarded.get(), dropped.get(),
                         connTracker.getActiveCount(),
                         sniExtractions.get(), classificationHits.get());
    }
}
