package com.joao.cyberaudit.service;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Service
public class RateLimitService {

    private final ConcurrentMap<String, Bucket> buckets = new ConcurrentHashMap<>();

    public boolean allow(String ip, int maxRequests, long windowMs) {
        Bucket bucket = buckets.computeIfAbsent(ip, k -> buildBucket(maxRequests, windowMs));
        return bucket.tryConsume(1);
    }

    private Bucket buildBucket(int maxRequests, long windowMs) {
        Bandwidth limit = Bandwidth.builder()
                .capacity(maxRequests)
                .refillGreedy(maxRequests, Duration.ofMillis(windowMs))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }
}