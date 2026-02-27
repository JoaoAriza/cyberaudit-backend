package com.joao.cyberaudit.service;

import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class RateLimitService {

    private static class Window {
        long windowStart;
        int count;

        Window(long windowStart, int count) {
            this.windowStart = windowStart;
            this.count = count;
        }
    }

    private final Map<String, Window> buckets = new ConcurrentHashMap<>();

    // Ex: 10 requests por 60s por chave
    public boolean allow(String key, int maxRequests, long windowMs) {
        long now = System.currentTimeMillis();
        Window w = buckets.compute(key, (k, cur) -> {
            if (cur == null || now - cur.windowStart > windowMs) {
                return new Window(now, 1);
            }
            cur.count++;
            return cur;
        });
        return w.count <= maxRequests;
    }
}