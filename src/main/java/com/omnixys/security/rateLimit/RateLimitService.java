package com.omnixys.security.rateLimit;

import java.time.Instant;

public class RateLimitService {

    private final RateLimitStore store;
    private final int defaultLimit;
    private final long defaultWindowMs;

    public RateLimitService(RateLimitStore store, int defaultLimit, long defaultWindowMs) {
        this.store = store;
        this.defaultLimit = defaultLimit;
        this.defaultWindowMs = defaultWindowMs;
    }

    public RateLimitResult isAllowed(String key) {
        return isAllowed(key, defaultLimit, defaultWindowMs);
    }

    public RateLimitResult isAllowed(String key, int limit, long windowMs) {
        long windowSeconds = Math.max(1, (windowMs + 999) / 1000);
        long current = store.increment(key);
        if (current == 1) {
            store.expire(key, windowSeconds);
        }
        long ttl = store.ttl(key);
        boolean allowed = current <= limit;
        long remaining = Math.max(limit - current, 0);
        long resetAt = Instant.now().toEpochMilli() + (ttl > 0 ? ttl * 1000 : windowMs);

        return new RateLimitResult(allowed, ttl > 0 ? ttl : windowSeconds, remaining, resetAt);
    }

    public record RateLimitResult(
            boolean allowed,
            long retryAfterSeconds,
            long remaining,
            long resetAtEpochMs
    ) {}

    public interface RateLimitStore {
        long increment(String key);
        long ttl(String key);
        void expire(String key, long seconds);
    }
}
