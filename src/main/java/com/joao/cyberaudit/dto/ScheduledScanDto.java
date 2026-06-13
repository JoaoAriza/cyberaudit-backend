package com.joao.cyberaudit.dto;

import com.joao.cyberaudit.model.ScheduledScan;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
public class ScheduledScanDto {
    private UUID          id;
    private String        host;
    private boolean       active;
    private String        frequency;
    private int           preferredHour;
    private LocalDateTime nextRun;
    private LocalDateTime lastRun;
    private boolean       enabled;
    private boolean       notifyEmail;
    private LocalDateTime createdAt;

    public static ScheduledScanDto from(ScheduledScan s) {
        ScheduledScanDto dto = new ScheduledScanDto();
        dto.id            = s.getId();
        dto.host          = s.getHost();
        dto.active        = s.isActive();
        dto.frequency     = s.getFrequency().name();
        dto.preferredHour = s.getPreferredHour();
        dto.nextRun       = s.getNextRun();
        dto.lastRun       = s.getLastRun();
        dto.enabled       = s.isEnabled();
        dto.notifyEmail   = s.isNotifyEmail();
        dto.createdAt     = s.getCreatedAt();
        return dto;
    }
}
