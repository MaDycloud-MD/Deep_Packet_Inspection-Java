package com.dpi.loadbalancer;

import com.dpi.fastpath.ThreadSafeQueue;
import com.dpi.types.FiveTuple;
import com.dpi.types.PacketJob;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Single load-balancer thread: receives packets and dispatches them to FP
 * worker queues using five-tuple hashing for flow affinity.
 */
public class LoadBalancer implements Runnable {

    private final int lbId;
    private final int fpStartId;
    public final ThreadSafeQueue<PacketJob>       inputQueue;
    private final List<ThreadSafeQueue<PacketJob>> fpQueues;

    private Thread           thread;
    private volatile boolean running = false;

    private final AtomicLong  received    = new AtomicLong();
    private final AtomicLong  dispatched  = new AtomicLong();
    private final long[]      perFpCounts;

    public LoadBalancer(int lbId, List<ThreadSafeQueue<PacketJob>> fpQueues, int fpStartId) {
        this.lbId        = lbId;
        this.fpStartId   = fpStartId;
        this.fpQueues    = fpQueues;
        this.inputQueue  = new ThreadSafeQueue<>(10_000);
        this.perFpCounts = new long[fpQueues.size()];
    }

    // ---- lifecycle ----

    public void start() {
        if (running) return;
        running = true;
        thread  = new Thread(this, "LB-" + lbId);
        thread.setDaemon(true);
        thread.start();
        System.out.printf("[LB%d] Started (serving FP%d-FP%d)%n",
                lbId, fpStartId, fpStartId + fpQueues.size() - 1);
    }

    public void stop() {
        if (!running) return;
        running = false;
        inputQueue.shutdown();
        if (thread != null) {
            try { thread.join(3000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        }
        System.out.println("[LB" + lbId + "] Stopped");
    }

    @Override
    public void run() {
        while (running) {
            Optional<PacketJob> opt = inputQueue.popWithTimeout(100);
            if (opt.isEmpty()) continue;

            received.incrementAndGet();
            PacketJob job = opt.get();

            int idx = selectFp(job.tuple);
            fpQueues.get(idx).push(job);
            dispatched.incrementAndGet();
            perFpCounts[idx]++;
        }
    }

    private int selectFp(FiveTuple tuple) {
        return Math.abs(tuple.hashCode()) % fpQueues.size();
    }

    // ---- stats ----

    public int getId() { return lbId; }

    public record Stats(long received, long dispatched, long[] perFp) {}

    public Stats getStats() {
        return new Stats(received.get(), dispatched.get(), perFpCounts.clone());
    }
}
