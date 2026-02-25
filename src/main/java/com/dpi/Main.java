package com.dpi;

import com.dpi.engine.DPIEngine;
import com.dpi.tools.GenerateTestPcap;

/**
 * DPI Engine — command-line entry point.
 *
 * Sub-commands:
 *   run      <input.pcap> <output.pcap> [options]   (default if no sub-command)
 *   generate [output.pcap]                           generates test traffic PCAP
 *
 * Options for 'run':
 *   --block-ip <ip>        Block traffic from a source IP
 *   --block-app <app>      Block application (YouTube, Facebook, etc.)
 *   --block-domain <dom>   Block domain (wildcards: *.facebook.com)
 *   --block-port <port>    Block destination port
 *   --rules <file>         Load rules from file
 *   --lbs <n>              Number of load balancer threads (default 2)
 *   --fps <n>              FP threads per LB (default 2)
 *   --verbose              Enable verbose output
 */
public class Main {

    public static void main(String[] args) throws Exception {
        if (args.length == 0) { printUsage(); System.exit(1); }

        // Sub-command dispatch
        if (args[0].equals("generate")) {
            String out = args.length > 1 ? args[1] : "test_dpi.pcap";
            GenerateTestPcap.main(new String[]{out});
            return;
        }

        // Default: 'run' mode — first two args are input/output files
        if (args.length < 2) { printUsage(); System.exit(1); }

        String inputFile  = args[0];
        String outputFile = args[1];

        int     numLbs   = 2;
        int     fpsPerLb = 2;
        boolean verbose  = false;

        java.util.List<String>  blockIps     = new java.util.ArrayList<>();
        java.util.List<String>  blockApps    = new java.util.ArrayList<>();
        java.util.List<String>  blockDomains = new java.util.ArrayList<>();
        java.util.List<Integer> blockPorts   = new java.util.ArrayList<>();
        String rulesFile = null;

        for (int i = 2; i < args.length; i++) {
            switch (args[i]) {
                case "--block-ip"     -> blockIps.add(args[++i]);
                case "--block-app"    -> blockApps.add(args[++i]);
                case "--block-domain" -> blockDomains.add(args[++i]);
                case "--block-port"   -> blockPorts.add(Integer.parseInt(args[++i]));
                case "--rules"        -> rulesFile = args[++i];
                case "--lbs"          -> numLbs   = Integer.parseInt(args[++i]);
                case "--fps"          -> fpsPerLb = Integer.parseInt(args[++i]);
                case "--verbose"      -> verbose  = true;
                case "--help", "-h"   -> { printUsage(); System.exit(0); }
                default -> System.err.println("Unknown option: " + args[i]);
            }
        }

        DPIEngine engine = new DPIEngine(new DPIEngine.Config(numLbs, fpsPerLb, verbose));

        if (rulesFile != null) engine.loadRules(rulesFile);
        blockIps.forEach(engine::blockIp);
        blockApps.forEach(engine::blockApp);
        blockDomains.forEach(engine::blockDomain);
        blockPorts.forEach(engine::blockPort);

        boolean ok = engine.processFile(inputFile, outputFile);

        if (ok) {
            System.out.println("\nProcessing complete!");
            System.out.println("Output written to: " + outputFile);
        } else {
            System.err.println("Processing failed.");
            System.exit(1);
        }
    }

    private static void printUsage() {
        System.out.println("""
                
                ╔══════════════════════════════════════════════════════════════╗
                ║              DPI ENGINE v2.0 (Java, Multi-threaded)           ║
                ╚══════════════════════════════════════════════════════════════╝
                
                Usage:
                  java -jar dpi-engine.jar <input.pcap> <output.pcap> [options]
                  java -jar dpi-engine.jar generate [output.pcap]
                
                Sub-commands:
                  generate [file]   Generate a test PCAP with sample traffic
                                    (default output: test_dpi.pcap)
                
                Options:
                  --block-ip <ip>        Block packets from source IP
                  --block-app <app>      Block application (YouTube, Netflix, etc.)
                  --block-domain <dom>   Block domain (wildcards: *.tiktok.com)
                  --block-port <port>    Block destination port
                  --rules <file>         Load blocking rules from file
                  --lbs <n>              Number of load balancer threads (default: 2)
                  --fps <n>              FP threads per LB (default: 2)
                  --verbose              Enable verbose output
                
                Examples:
                  # Generate test data
                  java -jar dpi-engine.jar generate test_dpi.pcap
                
                  # Basic run
                  java -jar dpi-engine.jar test_dpi.pcap output.pcap
                
                  # Block YouTube and TikTok
                  java -jar dpi-engine.jar test_dpi.pcap output.pcap \\
                      --block-app YouTube --block-app TikTok
                
                  # Block by IP
                  java -jar dpi-engine.jar test_dpi.pcap output.pcap \\
                      --block-ip 192.168.1.50
                
                  # Wildcard domain block
                  java -jar dpi-engine.jar test_dpi.pcap output.pcap \\
                      --block-domain "*.facebook.com"
                
                  # Use more threads + load rules from file
                  java -jar dpi-engine.jar input.pcap output.pcap \\
                      --lbs 4 --fps 4 --rules rules.txt
                
                Supported Apps:
                  Google, YouTube, Facebook, Instagram, Twitter, Netflix, Amazon,
                  Microsoft, Apple, WhatsApp, Telegram, TikTok, Spotify, Zoom, Discord,
                  GitHub, Cloudflare
                """);
    }
}
