package com.omnixys.security.autoconfigure;

import com.omnixys.security.rateLimit.RateLimitService;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Duration;

public class RedisRateLimitStore implements RateLimitService.RateLimitStore {

    private final StringRedisTemplate redis;

    public RedisRateLimitStore(StringRedisTemplate redis) {
        this.redis = redis;
    }

    @Override
    public long increment(String key) {
        Long val = redis.opsForValue().increment(key);
        return val != null ? val : 0;
    }

    @Override
    public long ttl(String key) {
        Long ttl = redis.getExpire(key);
        return ttl != null ? ttl : -1;
    }

    @Override
    public void expire(String key, long seconds) {
        redis.expire(key, Duration.ofSeconds(seconds));
    }
}
