package com.joao.cyberaudit.service;

import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class ScanCacheService {

    private static class Entry<T> {
        final T value;
        final long expiresAt;

        Entry(T value, long expiresAt) {
            this.value = value;
            this.expiresAt = expiresAt;
        }
    }

    private final Map<String, Entry<Object>> cache = new ConcurrentHashMap<>();

    public <T> T get(String key, Class<T> type) {
        Entry<Object> e = cache.get(key);
        if (e == null) return null;
        if (System.currentTimeMillis() > e.expiresAt) {
            cache.remove(key);
            return null;
        }
        return type.cast(e.value);
    }

    public void put(String key, Object value, long ttlMs) {
        cache.put(key, new Entry<>(value, System.currentTimeMillis() + ttlMs));
    }

    public void invalidate(String key) {
        cache.remove(key);
    }
}