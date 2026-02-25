package com.dpi.engine;

import com.dpi.fastpath.FastPathProcessor;
import com.dpi.fastpath.ThreadSafeQueue;
import com.dpi.loadbalancer.LoadBalancer;
import com.dpi.pcap.PcapReader;
import com.dpi.parser.PacketParser;
import com.dpi.rules.RuleManager;
import com.dpi.tracker.Connection;
import com.dpi.types.*;

import java.io.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Multi-threaded DPI engine.
 *
 *   PcapReader (main thread)
 *       └─[hash % numLbs]──► LoadBalancer threads
 *                                └─[hash % fpsPerLb]──► FastPath threads
 *                                                           └──► OutputWriter thread
 */
public class DPIEngine {

    public record Config(int numLoadBalancers, int fpsPerLb, boolean verbose) {
        public Config() { this(2, 2, false); }
    }

    private final Config      config;
    private final RuleManager ruleManager = new RuleManager();
    private final DPIStats    stats       = new DPIStats();

    // Pipeline components
    private final List<FastPathProcessor> fps      = new ArrayList<>();
    private final List<LoadBalancer>      lbs      = new ArrayList<>();
    private final ThreadSafeQueue<OutputItem> outputQueue = new ThreadSafeQueue<>(20_000);

    private Thread  outputThread;
    private volatile boolean outputRunning = false;

    private record OutputItem(PacketJob job, PacketAction action) {}

    // ---- construction ----

    public DPIEngine(Config config) {
        this.config = config;
        printBanner();
    }

    public DPIEngine() { this(new Config()); }

    // ---- rule helpers ----

    public void blockIp(String ip)        { ruleManager.blockIp(ip); }
    public void blockApp(String app)      { ruleManager.blockApp(app); }
    public void blockApp(AppType app)     { ruleManager.blockApp(app); }
    public void blockDomain(String dom)   { ruleManager.blockDomain(dom); }
    public void blockPort(int port)       { ruleManager.blockPort(port); }
    public void loadRules(String file)    { ruleManager.loadRules(file); }
    public RuleManager getRuleManager()   { return ruleManager; }
    public DPIStats getStats()            { return stats; }

    // ---- main entry point ----

    public boolean processFile(String inputFile, String outputFile) {
        buildPipeline();
        startOutputWriter(outputFile);

        fps.forEach(FastPathProcessor::start);
        lbs.forEach(LoadBalancer::start);

        System.out.println("[Reader] Processing packets...");

        long packetId   = 0;
        long totalRead  = 0;

        try (PcapReader reader = new PcapReader()) {
            if (!reader.open(inputFile)) return false;

            PcapReader.RawPacket raw;
            while ((raw = reader.readNextPacket()) != null) {
                PacketJob job = PacketParser.toJob(packetId++, raw);
                if (job == null) continue;

                totalRead++;
                stats.totalPackets.incrementAndGet();
                stats.totalBytes.addAndGet(raw.data.length);
                if (job.tuple.protocol == PacketParser.PROTO_TCP)       stats.tcpPackets.incrementAndGet();
                else if (job.tuple.protocol == PacketParser.PROTO_UDP)  stats.udpPackets.incrementAndGet();
                else                                                      stats.otherPackets.incrementAndGet();

                getLbForPacket(job.tuple).inputQueue.push(job);
            }
        } catch (IOException e) {
            System.err.println("[DPIEngine] Read error: " + e.getMessage());
            return false;
        }

        System.out.println("[Reader] Done reading " + totalRead + " packets");

        drainAndStop();
        printReport();
        return true;
    }

    // ---- pipeline construction ----

    private void buildPipeline() {
        int totalFps = config.numLoadBalancers() * config.fpsPerLb();

        for (int i = 0; i < totalFps; i++) {
            fps.add(new FastPathProcessor(i, ruleManager,
                    (job, action) -> outputQueue.push(new OutputItem(job, action))));
        }

        for (int lb = 0; lb < config.numLoadBalancers(); lb++) {
            List<ThreadSafeQueue<PacketJob>> slice = new ArrayList<>();
            for (int f = 0; f < config.fpsPerLb(); f++) {
                slice.add(fps.get(lb * config.fpsPerLb() + f).inputQueue);
            }
            lbs.add(new LoadBalancer(lb, slice, lb * config.fpsPerLb()));
        }

        System.out.printf("[DPIEngine] Pipeline: %d LBs × %d FPs = %d worker threads%n",
                config.numLoadBalancers(), config.fpsPerLb(), totalFps);
    }

    private LoadBalancer getLbForPacket(FiveTuple tuple) {
        return lbs.get(Math.abs(tuple.hashCode()) % lbs.size());
    }

    // ---- output writer ----

    private void startOutputWriter(String outputFile) {
        outputRunning = true;
        outputThread  = new Thread(() -> {
            try (DataOutputStream out = new DataOutputStream(
                    new BufferedOutputStream(new FileOutputStream(outputFile)))) {

                PcapReader.writeGlobalHeader(out);

                while (outputRunning) {
                    Optional<OutputItem> opt = outputQueue.popWithTimeout(100);
                    if (opt.isEmpty()) continue;

                    OutputItem item = opt.get();
                    if (item.action() == PacketAction.FORWARD) {
                        stats.forwardedPackets.incrementAndGet();
                        PcapReader.RawPacket p = new PcapReader.RawPacket();
                        p.tsSec  = item.job().tsSec;
                        p.tsUsec = item.job().tsUsec;
                        p.data   = item.job().data;
                        PcapReader.writePacket(out, p);
                    } else {
                        stats.droppedPackets.incrementAndGet();
                    }
                }
            } catch (IOException e) {
                System.err.println("[OutputWriter] Error: " + e.getMessage());
            }
        }, "OutputWriter");
        outputThread.setDaemon(true);
        outputThread.start();
    }

    // ---- drain / stop ----

    private void drainAndStop() {
        lbs.forEach(lb -> { while (lb.inputQueue.size() > 0) sleepMs(50); });
        fps.forEach(fp -> { while (fp.inputQueue.size() > 0) sleepMs(50); });
        sleepMs(300);

        lbs.forEach(LoadBalancer::stop);
        fps.forEach(FastPathProcessor::stop);

        while (outputQueue.size() > 0) sleepMs(50);
        outputRunning = false;
        outputQueue.shutdown();
        try { if (outputThread != null) outputThread.join(3000); }
        catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    // ---- reporting ----

    /**
     * Prints the full report matching the sample output in README.md.
     */
    private void printReport() {
        // Aggregate per-FP connection data
        Map<AppType, Long> appCounts = new EnumMap<>(AppType.class);
        Map<String, Long>  sniCounts = new HashMap<>();

        for (FastPathProcessor fp : fps) {
            fp.getConnectionTracker().forEach(conn -> {
                appCounts.merge(conn.appType, 1L, Long::sum);
                if (!conn.sni.isEmpty()) sniCounts.merge(conn.sni, 1L, Long::sum);
            });
        }

        long total     = stats.totalPackets.get();
        long forwarded = stats.forwardedPackets.get();
        long dropped   = stats.droppedPackets.get();
        long tcp       = stats.tcpPackets.get();
        long udp       = stats.udpPackets.get();

        System.out.println();
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                      PROCESSING REPORT                       ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.printf( "║ Total Packets:      %10d                             ║%n", total);
        System.out.printf( "║ Total Bytes:        %10d                             ║%n", stats.totalBytes.get());
        System.out.printf( "║ TCP Packets:        %10d                             ║%n", tcp);
        System.out.printf( "║ UDP Packets:        %10d                             ║%n", udp);
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.printf( "║ Forwarded:          %10d                             ║%n", forwarded);
        System.out.printf( "║ Dropped:            %10d                             ║%n", dropped);
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println("║ THREAD STATISTICS                                             ║");

        for (LoadBalancer lb : lbs) {
            LoadBalancer.Stats ls = lb.getStats();
            System.out.printf("║   LB%d dispatched:  %10d                             ║%n",
                    lb.getId(), ls.dispatched());
        }
        for (FastPathProcessor fp : fps) {
            FastPathProcessor.Stats fs = fp.getStats();
            System.out.printf("║   FP%d processed:   %10d                             ║%n",
                    fp.getId(), fs.processed());
        }

        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println("║                   APPLICATION BREAKDOWN                      ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");

        appCounts.entrySet().stream()
                .sorted(Map.Entry.<AppType, Long>comparingByValue().reversed())
                .forEach(e -> {
                    double pct = total > 0 ? 100.0 * e.getValue() / total : 0;
                    int    bar = (int)(pct / 5);
                    boolean blocked = ruleManager.isAppBlocked(e.getKey());
                    System.out.printf("║ %-15s %8d %5.1f%% %-20s%s║%n",
                            e.getKey().toString(), e.getValue(), pct,
                            "#".repeat(Math.min(bar, 20)),
                            blocked ? " (BLOCKED)    " : "              ");
                });

        System.out.println("╚══════════════════════════════════════════════════════════════╝");

        if (!sniCounts.isEmpty()) {
            System.out.println("\n[Detected Domains/SNIs]");
            sniCounts.entrySet().stream()
                    .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                    .limit(25)
                    .forEach(e -> System.out.printf("  - %-40s → %s%n",
                            e.getKey(), AppType.fromSni(e.getKey())));
        }
    }

    private void printBanner() {
        System.out.println();
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║            DPI ENGINE v2.0 (Java, Multi-threaded)             ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.printf( "║ Load Balancers: %-3d  FPs per LB: %-3d  Total FPs: %-3d         ║%n",
                config.numLoadBalancers(), config.fpsPerLb(),
                config.numLoadBalancers() * config.fpsPerLb());
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
    }

    private static void sleepMs(long ms) {
        try { Thread.sleep(ms); }
        catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }
}
