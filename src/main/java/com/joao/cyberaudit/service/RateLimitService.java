package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.Role;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Service
public class RateLimitService {

    public static final int GUEST_RPM    = 5;
    public static final int EMPLOYEE_RPM = 60;
    public static final int ADMIN_RPM    = 120;

    private final ConcurrentMap<String, Bucket> buckets = new ConcurrentHashMap<>();

    public boolean allow(String key, AppUser currentUser) {
        // OWNER não tem rate limit de requests por minuto
        if (currentUser != null && currentUser.getRole() == Role.OWNER) {
            return true;
        }

        int rpm = resolveRpm(currentUser);
        Bucket bucket = buckets.computeIfAbsent(
                buildKey(key, currentUser),
                k -> buildBucket(rpm)
        );
        return bucket.tryConsume(1);
    }

    public boolean allow(String key, int maxRequests, long windowMs) {
        Bucket bucket = buckets.computeIfAbsent(key, k ->
                Bucket.builder()
                        .addLimit(Bandwidth.builder()
                                .capacity(maxRequests)
                                .refillGreedy(maxRequests,
                                        Duration.ofMillis(windowMs))
                                .build())
                        .build()
        );
        return bucket.tryConsume(1);
    }

    private int resolveRpm(AppUser user) {
        if (user == null) return GUEST_RPM;
        return switch (user.getRole()) {
            case ADMIN         -> ADMIN_RPM;
            case FREE_EMPLOYEE -> EMPLOYEE_RPM;
            default            -> GUEST_RPM;
        };
    }

    private String buildKey(String ip, AppUser user) {
        if (user != null) return "user:" + user.getId().toString();
        return "ip:" + ip;
    }

    private Bucket buildBucket(int rpm) {
        return Bucket.builder()
                .addLimit(Bandwidth.builder()
                        .capacity(rpm)
                        .refillGreedy(rpm, Duration.ofMinutes(1))
                        .build())
                .build();
    }
}