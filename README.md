# DPI Engine (Java)

A high-performance **Deep Packet Inspection (DPI) Engine** built in Java
17+ using Maven.\
It processes PCAP files, performs stateful connection tracking, extracts
application-layer metadata (TLS SNI, HTTP Host, DNS queries), applies
blocking rules, and writes filtered output to a new PCAP.

------------------------------------------------------------------------

## Prerequisites

Make sure the following are installed:

-   **Java 17+** --- https://adoptium.net\
-   **Maven 3.6+** --- https://maven.apache.org

Verify installation:

``` bash
java -version    # should say 17 or higher
mvn -version     # should say 3.6 or higher
```

------------------------------------------------------------------------

## How to Compile & Run

### Step 1 --- Compile

``` bash
cd Deep_Packet_Inspection-Java
mvn package -q
```

Maven reads `pom.xml`, compiles all Java files, and produces a fat JAR:

    target/dpi-engine.jar

------------------------------------------------------------------------

### Step 2 --- Generate Test Traffic

``` bash
java -jar target/dpi-engine.jar generate test_dpi.pcap
```

This generates a synthetic PCAP file containing:

-   16 TLS connections (YouTube, Facebook, TikTok, etc.)
-   2 HTTP connections
-   4 DNS queries
-   5 packets from a malicious source IP

All packets are handcrafted byte-by-byte --- no Wireshark required.

------------------------------------------------------------------------

### Step 3 --- Run the Engine

#### Basic (no blocking rules)

``` bash
java -jar target/dpi-engine.jar test_dpi.pcap output.pcap
```

#### Block Applications

``` bash
java -jar target/dpi-engine.jar test_dpi.pcap output.pcap     --block-app YouTube --block-app TikTok
```

#### Block Source IP

``` bash
java -jar target/dpi-engine.jar test_dpi.pcap output.pcap     --block-ip 192.168.1.50
```

#### Block Domain (Wildcard Support)

``` bash
java -jar target/dpi-engine.jar test_dpi.pcap output.pcap     --block-domain "*.facebook.com"
```

#### Combine Rules + Tune Threads

``` bash
java -jar target/dpi-engine.jar test_dpi.pcap output.pcap     --block-app YouTube     --block-ip 192.168.1.50     --lbs 2     --fps 4
```
------------------------------------------------------------------------
## To Unblock in future use this command

### Run with rules and save them to a file 

``` bash
java -jar dpi-engine.jar test_dpi.pcap output.pcap \
--block-app YouTube --block-app TikTok \
--block-ip 192.168.1.50 \
--save-rules rules.txt
```

### Next time, just load the file
``` bash
java -jar dpi-engine.jar test_dpi.pcap output.pcap --rules rules.txt
```
## --unblock-* CLI flags

### Unblock a single app
``` bash
java -jar dpi-engine.jar input.pcap output.pcap \
--rules rules.txt --unblock-app YouTube
```

#### Unblock a specific IP
``` bash
java -jar dpi-engine.jar input.pcap output.pcap \
--rules rules.txt --unblock-ip 192.168.1.50
```

####  Unblock a domain (exact same string you blocked with)
``` bash
java -jar dpi-engine.jar input.pcap output.pcap \
--rules rules.txt --unblock-domain "*.facebook.com"
```

#### Unblock a port
``` bash
java -jar dpi-engine.jar input.pcap output.pcap \
--rules rules.txt --unblock-port 6881
```


#### Block everything, then surgically unblock Netflix
``` bash 
java -jar dpi-engine.jar input.pcap output.pcap \
--block-app YouTube --block-app Netflix --block-app TikTok \
--unblock-app Netflix \
--save-rules rules.txt
```
### Net result: YouTube and TikTok blocked, Netflix passes through

------------------------------------------------------------------------
 
## How It Works — The Full Journey of One Packet
        ```
        test_dpi.pcap
        │
        │  [Main thread — PcapReader]
        │  Reads raw bytes frame by frame.
        │  PacketParser strips Ethernet→IP→TCP/UDP headers,
        │  records every layer offset, builds a PacketJob.
        │
        ▼
        hash(5-tuple) % 2
        │
        ├── LB-0 thread ─────────────────────────────┐
        └── LB-1 thread                              │
                │                                    │
                │  [LoadBalancer]                    │
                │  Re-hashes the same 5-tuple.       │
                │  Same flow ALWAYS lands on         │
                │  the same FP — this is critical    │
                │  for stateful tracking.            │
                │                                    │
    hash(5-tuple) % fpsPerLb                         │
                │                                    │
        ┌───────┴────────┐                  ┌────────┴────────┐
        FP-0             FP-1               FP-2             FP-3
        │
        │  [FastPathProcessor]
        │
        │  1. CONNECTION TRACKING
        │     Looks up (or creates) a Connection
        │     entry keyed by the 5-tuple.
        │     Tracks TCP state: SYN→ESTABLISHED→CLOSED.
        │
        │  2. DEEP PACKET INSPECTION
        │     If payload exists and flow not yet classified:
        │     • Port 443 → try TLS SNI extraction
        │       Parses the raw TLS Client Hello bytes,
        │       navigates to the SNI extension (type 0x0000),
        │       reads the hostname string: "www.youtube.com"
        │       Maps it → AppType.YOUTUBE
        │     • Port 80  → scan for "Host:" HTTP header
        │     • Port 53  → parse DNS question section
        │     • Fallback → classify by port number only
        │
        │  3. RULE CHECK
        │     RuleManager.shouldBlock(srcIp, dstPort, app, domain)
        │     Checks 4 independent rule sets with read locks:
        │       blocked IPs → blocked ports → blocked apps → blocked domains
        │     First match wins → DROP
        │     No match → FORWARD
        │
        │  4. Once a flow is blocked, every subsequent
        │     packet in that flow is dropped instantly
        │     without re-running DPI (conn.state == BLOCKED).
        │
        ▼
        OutputQueue
        │
        │  [OutputWriter thread]
        │  FORWARD → write packet to output.pcap
        │  DROP    → discard silently
        │
        ▼
        output.pcap  +  terminal report
------------------------------------------------------------------------

## Architecture Highlights

### Two-Level Hashing

-   Level 1 → Load Balancers (LB)
-   Level 2 → Fast Path Processors (FP)
-   Controlled via runtime flags:
    -   `--lbs`
    -   `--fps`

This enables horizontal scaling: - Increase LBs → handle more ingress
bandwidth - Increase FPs → handle more DPI compute power

Why two levels of hashing (LB then FP)? It scales horizontally. You can add more LBs to 
handle more ingress bandwidth, and more FPs to handle more DPI compute — independently. 
The --lbs and --fps flags control this at runtime.

Why does each FP have its own connection table? Because consistent hashing guarantees 
the same flow always hits the same FP, there is zero contention on the flow table. 
No locks needed there at all — the only locks in the whole system are in RuleManager (read/write 
rules concurrently) and the ThreadSafeQueue (hand-off between threads).

------------------------------------------------------------------------

### Lock-Free Flow Tables

Each FastPathProcessor maintains its own connection table.

Because consistent hashing guarantees the same flow always lands on the
same FP: - No shared flow state - No locks required for connection
tracking - High throughput design

Only shared locks exist in: - `RuleManager` (for rule updates) -
`ThreadSafeQueue` (inter-thread communication)

------------------------------------------------------------------------

## Output

The engine produces:

-   `output.pcap` (filtered traffic)
-   Terminal summary report

You can compare `test_dpi.pcap` and `output.pcap` using Wireshark to
visually inspect filtered packets.

------------------------------------------------------------------------

## Summary

This DPI Engine demonstrates:

-   Stateful connection tracking
-   TLS SNI extraction
-   HTTP header parsing
-   DNS query parsing
-   Rule-based blocking
-   Lock-minimized multi-threaded architecture
-   Horizontally scalable design

Built for performance, clarity, and extensibility.
