package com.joao.cyberaudit.dto;

import com.joao.cyberaudit.model.AuditLog;

import java.util.UUID;

public record AuditLogDto(
        UUID id,
        UUID userId,
        String userEmail,
        String userName,
        String action,
        String details,
        String ipAddress,
        String timestamp,
        boolean success
) {
    public static AuditLogDto from(AuditLog log) {
        return new AuditLogDto(
                log.getId(),
                log.getUserId(),
                log.getUserEmail(),
                log.getUserName(),
                log.getAction().name(),
                log.getDetails(),
                log.getIpAddress(),
                log.getTimestamp().toString(),
                log.isSuccess()
        );
    }
}
