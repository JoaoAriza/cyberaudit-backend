package com.joao.cyberaudit.service;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class ScanCacheService {

    private final Cache<String, Object> cache = Caffeine.newBuilder()
            .expireAfterWrite(2, TimeUnit.MINUTES)
            .maximumSize(500)   // LRU: descarta os menos usados quando chega no limite
            .build();

    public <T> T get(String key, Class<T> type) {
        Object value = cache.getIfPresent(key);
        if (value == null) return null;
        return type.isInstance(value) ? type.cast(value) : null;
    }
    
    public void put(String key, Object value) {
        cache.put(key, value);
    }

    public void invalidate(String key) {
        cache.invalidate(key);
    }
}