package com.omnixys.security.autoconfigure;

import com.omnixys.security.revocation.TokenRevocationService;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Duration;

public class RedisRevocationStore implements TokenRevocationService.RevocationStore {

    private final StringRedisTemplate redis;

    public RedisRevocationStore(StringRedisTemplate redis) {
        this.redis = redis;
    }

    @Override
    public void set(String key, String value, long ttlSec) {
        redis.opsForValue().set(key, value, Duration.ofSeconds(ttlSec));
    }

    @Override
    public boolean exists(String key) {
        Boolean exists = redis.hasKey(key);
        return Boolean.TRUE.equals(exists);
    }
}
