package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
@AllArgsConstructor
public class ScanSummary {
    private UUID id;
    private String url;
    private String host;
    private LocalDateTime scannedAt;
    private boolean activeMode;
    private int score;
    private RiskLevel riskLevel;
    private ScanOrigin origin;

    public static ScanSummary from(ScanRecord record) {
        return new ScanSummary(
                record.getId(),
                record.getUrl(),
                record.getHost(),
                record.getScannedAt(),
                record.isActiveMode(),
                record.getScore(),
                record.getRiskLevel(),
                record.getOrigin() != null ? record.getOrigin() : ScanOrigin.MANUAL
        );
    }
}