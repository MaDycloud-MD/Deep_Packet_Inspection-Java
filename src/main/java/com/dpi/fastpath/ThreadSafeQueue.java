package com.dpi.fastpath;

import java.util.ArrayDeque;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Bounded, thread-safe FIFO queue with blocking push/pop and graceful shutdown.
 * Mirrors the C++ ThreadSafeQueue<T>.
 */
public class ThreadSafeQueue<T> {

    private final int capacity;
    private final ArrayDeque<T> queue;
    private volatile boolean shutdown = false;

    private final ReentrantLock lock      = new ReentrantLock();
    private final Condition     notEmpty  = lock.newCondition();
    private final Condition     notFull   = lock.newCondition();

    public ThreadSafeQueue(int capacity) {
        this.capacity = capacity;
        this.queue    = new ArrayDeque<>(Math.min(capacity, 4096));
    }

    /** Blocking push — waits until space is available or queue is shut down. */
    public boolean push(T item) {
        lock.lock();
        try {
            while (queue.size() >= capacity && !shutdown) {
                notFull.await(50, TimeUnit.MILLISECONDS);
            }
            if (shutdown) return false;
            queue.addLast(item);
            notEmpty.signal();
            return true;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        } finally {
            lock.unlock();
        }
    }

    /** Pop with timeout. Returns empty if no item available within timeoutMs. */
    public Optional<T> popWithTimeout(long timeoutMs) {
        lock.lock();
        try {
            long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs);
            while (queue.isEmpty() && !shutdown) {
                long remaining = deadline - System.nanoTime();
                if (remaining <= 0) return Optional.empty();
                notEmpty.await(remaining, TimeUnit.NANOSECONDS);
            }
            if (queue.isEmpty()) return Optional.empty();
            T item = queue.pollFirst();
            notFull.signal();
            return Optional.ofNullable(item);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Optional.empty();
        } finally {
            lock.unlock();
        }
    }

    public void shutdown() {
        lock.lock();
        try {
            shutdown = true;
            notEmpty.signalAll();
            notFull.signalAll();
        } finally {
            lock.unlock();
        }
    }

    public boolean isShutdown() { return shutdown; }

    public int size() {
        lock.lock();
        try { return queue.size(); } finally { lock.unlock(); }
    }
}
