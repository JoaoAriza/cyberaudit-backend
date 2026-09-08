package com.joao.cyberaudit.dto;

import com.joao.cyberaudit.model.AuditLog;

import java.time.LocalDateTime;
import java.util.UUID;

public record AuditLogDto(
        UUID id,
        UUID userId,
        String userEmail,
        String userName,
        String action,
        String details,
        String ipAddress,
        // LocalDateTime, e NÃO String: o carimbo de fuso do TimeConfig só alcança o
        // que chega ao Jackson como data. Convertido para String aqui, o instante saía
        // como "2026-09-08T19:03:51" e o navegador lia isso como hora LOCAL — era o
        // que fazia o painel admin mostrar os eventos três horas no futuro.
        LocalDateTime timestamp,
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
                log.getTimestamp(),
                log.isSuccess()
        );
    }
}
