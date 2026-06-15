package com.joao.cyberaudit.service;

import com.joao.cyberaudit.exception.GuestDailyLimitException;
import com.joao.cyberaudit.model.GuestScanLimit;
import com.joao.cyberaudit.repository.GuestScanLimitRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Service
public class GuestRateLimitService {

    public static final int DAILY_LIMIT = 5;

    private final GuestScanLimitRepository repository;

    public GuestRateLimitService(GuestScanLimitRepository repository) {
        this.repository = repository;
    }

    @Transactional
    public void checkAndIncrement(String ip) {
        LocalDate today = LocalDate.now();
        GuestScanLimit.GuestScanLimitId id =
                new GuestScanLimit.GuestScanLimitId(ip, today);

        GuestScanLimit limit = repository.findByIdIpAndIdScanDate(ip, today)
                .orElseGet(() -> new GuestScanLimit(id, 0, null));

        if (limit.getCount() >= DAILY_LIMIT) {
            throw new GuestDailyLimitException(
                    limit.getCount(),
                    DAILY_LIMIT,
                    today.plusDays(1).atStartOfDay()
            );
        }

        limit.setCount(limit.getCount() + 1);
        limit.setLastScanAt(LocalDateTime.now());
        repository.save(limit);
    }

    public int getRemainingScans(String ip) {
        return Math.max(0, DAILY_LIMIT - getTodayCount(ip));
    }

    private int getTodayCount(String ip) {
        return repository.findByIdIpAndIdScanDate(ip, LocalDate.now())
                .map(GuestScanLimit::getCount)
                .orElse(0);
    }
}