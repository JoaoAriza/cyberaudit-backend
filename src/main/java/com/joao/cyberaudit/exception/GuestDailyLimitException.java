package com.joao.cyberaudit.exception;

import lombok.Getter;
import java.time.LocalDateTime;

@Getter
public class GuestDailyLimitException extends RuntimeException {

    private final int currentCount;
    private final int dailyLimit;
    private final LocalDateTime resetsAt;

    public GuestDailyLimitException(int currentCount, int dailyLimit, LocalDateTime resetsAt) {
        super("Limite diário de scans atingido.");
        this.currentCount = currentCount;
        this.dailyLimit   = dailyLimit;
        this.resetsAt     = resetsAt;
    }
}