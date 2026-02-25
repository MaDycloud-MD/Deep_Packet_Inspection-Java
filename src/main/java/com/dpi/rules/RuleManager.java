package com.dpi.rules;

import com.dpi.types.AppType;
import com.dpi.types.FiveTuple;

import java.io.*;
import java.util.*;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Thread-safe rule manager for blocking by IP, application, domain, or port.
 * Uses separate ReadWriteLocks per category for maximum read concurrency.
 */
public class RuleManager {

    public enum BlockType { IP, APP, DOMAIN, PORT }

    public record BlockReason(BlockType type, String detail) {}

    // ---- per-category state + locks ----
    private final Set<Integer>  blockedIps      = new HashSet<>();
    private final ReadWriteLock ipLock          = new ReentrantReadWriteLock();

    private final Set<AppType>  blockedApps     = new HashSet<>();
    private final ReadWriteLock appLock         = new ReentrantReadWriteLock();

    private final Set<String>   blockedDomains  = new HashSet<>();
    private final List<String>  domainPatterns  = new ArrayList<>();
    private final ReadWriteLock domainLock      = new ReentrantReadWriteLock();

    private final Set<Integer>  blockedPorts    = new HashSet<>();
    private final ReadWriteLock portLock        = new ReentrantReadWriteLock();

    // -----------------------------------------------------------------------
    // IP blocking
    // -----------------------------------------------------------------------

    public void blockIp(String ip) {
        blockIp(FiveTuple.parseIp(ip));
    }

    public void blockIp(int ip) {
        ipLock.writeLock().lock();
        try { blockedIps.add(ip); } finally { ipLock.writeLock().unlock(); }
        System.out.println("[RuleManager] Blocked IP: " + FiveTuple.ipToString(ip));
    }

    public void unblockIp(int ip) {
        ipLock.writeLock().lock();
        try { blockedIps.remove(ip); } finally { ipLock.writeLock().unlock(); }
    }

    public boolean isIpBlocked(int ip) {
        ipLock.readLock().lock();
        try { return blockedIps.contains(ip); } finally { ipLock.readLock().unlock(); }
    }

    // -----------------------------------------------------------------------
    // App blocking
    // -----------------------------------------------------------------------

    public void blockApp(AppType app) {
        appLock.writeLock().lock();
        try { blockedApps.add(app); } finally { appLock.writeLock().unlock(); }
        System.out.println("[RuleManager] Blocked app: " + app);
    }

    public void blockApp(String appName) {
        for (AppType a : AppType.values()) {
            if (a.toString().equalsIgnoreCase(appName) || a.name().equalsIgnoreCase(appName)) {
                blockApp(a);
                return;
            }
        }
        System.err.println("[RuleManager] Unknown app: " + appName);
    }

    public void unblockApp(AppType app) {
        appLock.writeLock().lock();
        try { blockedApps.remove(app); } finally { appLock.writeLock().unlock(); }
    }

    public boolean isAppBlocked(AppType app) {
        appLock.readLock().lock();
        try { return blockedApps.contains(app); } finally { appLock.readLock().unlock(); }
    }

    // -----------------------------------------------------------------------
    // Domain blocking
    // -----------------------------------------------------------------------

    public void blockDomain(String domain) {
        domainLock.writeLock().lock();
        try {
            if (domain.contains("*")) domainPatterns.add(domain.toLowerCase());
            else blockedDomains.add(domain.toLowerCase());
        } finally { domainLock.writeLock().unlock(); }
        System.out.println("[RuleManager] Blocked domain: " + domain);
    }

    public boolean isDomainBlocked(String domain) {
        if (domain == null || domain.isEmpty()) return false;
        String lower = domain.toLowerCase();

        domainLock.readLock().lock();
        try {
            if (blockedDomains.contains(lower)) return true;
            for (String pattern : domainPatterns) {
                if (matchesPattern(lower, pattern)) return true;
            }
        } finally { domainLock.readLock().unlock(); }
        return false;
    }

    private static boolean matchesPattern(String domain, String pattern) {
        // Handles *.example.com
        if (pattern.startsWith("*.")) {
            String suffix = pattern.substring(1); // .example.com
            if (domain.endsWith(suffix)) return true;
            if (domain.equals(pattern.substring(2))) return true; // bare domain
        }
        return false;
    }

    // -----------------------------------------------------------------------
    // Port blocking
    // -----------------------------------------------------------------------

    public void blockPort(int port) {
        portLock.writeLock().lock();
        try { blockedPorts.add(port); } finally { portLock.writeLock().unlock(); }
        System.out.println("[RuleManager] Blocked port: " + port);
    }

    public boolean isPortBlocked(int port) {
        portLock.readLock().lock();
        try { return blockedPorts.contains(port); } finally { portLock.readLock().unlock(); }
    }

    // -----------------------------------------------------------------------
    // Combined check
    // -----------------------------------------------------------------------

    public Optional<BlockReason> shouldBlock(int srcIp, int dstPort, AppType app, String domain) {
        if (isIpBlocked(srcIp))
            return Optional.of(new BlockReason(BlockType.IP, FiveTuple.ipToString(srcIp)));
        if (isPortBlocked(dstPort))
            return Optional.of(new BlockReason(BlockType.PORT, String.valueOf(dstPort)));
        if (isAppBlocked(app))
            return Optional.of(new BlockReason(BlockType.APP, app.toString()));
        if (isDomainBlocked(domain))
            return Optional.of(new BlockReason(BlockType.DOMAIN, domain));
        return Optional.empty();
    }

    // -----------------------------------------------------------------------
    // Persistence
    // -----------------------------------------------------------------------

    public boolean saveRules(String filename) {
        try (PrintWriter pw = new PrintWriter(new FileWriter(filename))) {
            pw.println("[BLOCKED_IPS]");
            ipLock.readLock().lock();
            try { blockedIps.forEach(ip -> pw.println(FiveTuple.ipToString(ip))); }
            finally { ipLock.readLock().unlock(); }

            pw.println("\n[BLOCKED_APPS]");
            appLock.readLock().lock();
            try { blockedApps.forEach(a -> pw.println(a.name())); }
            finally { appLock.readLock().unlock(); }

            pw.println("\n[BLOCKED_DOMAINS]");
            domainLock.readLock().lock();
            try {
                blockedDomains.forEach(pw::println);
                domainPatterns.forEach(pw::println);
            } finally { domainLock.readLock().unlock(); }

            pw.println("\n[BLOCKED_PORTS]");
            portLock.readLock().lock();
            try { blockedPorts.forEach(pw::println); }
            finally { portLock.readLock().unlock(); }

            System.out.println("[RuleManager] Rules saved to: " + filename);
            return true;
        } catch (IOException e) {
            System.err.println("[RuleManager] Failed to save rules: " + e.getMessage());
            return false;
        }
    }

    public boolean loadRules(String filename) {
        try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
            String line, section = "";
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;
                if (line.startsWith("[")) { section = line; continue; }
                switch (section) {
                    case "[BLOCKED_IPS]"     -> blockIp(line);
                    case "[BLOCKED_APPS]"    -> blockApp(line);
                    case "[BLOCKED_DOMAINS]" -> blockDomain(line);
                    case "[BLOCKED_PORTS]"   -> blockPort(Integer.parseInt(line));
                }
            }
            System.out.println("[RuleManager] Rules loaded from: " + filename);
            return true;
        } catch (IOException e) {
            System.err.println("[RuleManager] Failed to load rules: " + e.getMessage());
            return false;
        }
    }

    public void clearAll() {
        ipLock.writeLock().lock();    try { blockedIps.clear(); }       finally { ipLock.writeLock().unlock(); }
        appLock.writeLock().lock();   try { blockedApps.clear(); }      finally { appLock.writeLock().unlock(); }
        domainLock.writeLock().lock();try { blockedDomains.clear(); domainPatterns.clear(); } finally { domainLock.writeLock().unlock(); }
        portLock.writeLock().lock();  try { blockedPorts.clear(); }     finally { portLock.writeLock().unlock(); }
        System.out.println("[RuleManager] All rules cleared");
    }
}
