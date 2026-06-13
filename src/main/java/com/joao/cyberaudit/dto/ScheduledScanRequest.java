package com.joao.cyberaudit.dto;

import lombok.Data;

@Data
public class ScheduledScanRequest {
    private String  host;
    private boolean active;
    private String  frequency;   // "DAILY" | "WEEKLY"
    private int     preferredHour; // 0-23 UTC
    private boolean notifyEmail;
}
