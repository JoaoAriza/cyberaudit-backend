package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.AuditAction;
import com.joao.cyberaudit.model.AuditLog;
import com.joao.cyberaudit.repository.AuditLogRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Registra ações de usuário no log de auditoria.
 *
 * Regras:
 * - Nunca lança exceção — falhas de log não devem interromper o fluxo principal.
 * - IP é extraído do contexto HTTP atual via RequestContextHolder.
 * - Suporta logs pré-autenticação (ex: LOGIN_FAILED) com userId/accountId nulos.
 */
@Service
public class AuditService {

    private final AuditLogRepository auditLogRepository;

    public AuditService(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    /**
     * Registra uma ação de um usuário autenticado (sucesso implícito).
     */
    public void log(AppUser user, AuditAction action, String details) {
        log(
                user.getAccount() != null ? user.getAccount().getId() : null,
                user.getId(),
                user.getEmail(),
                user.getName(),
                action,
                details,
                true
        );
    }

    /**
     * Registra uma ação com controle total dos campos.
     * Usado para LOGIN_FAILED (sem userId/accountId) e ações com success=false.
     */
    public void log(UUID accountId, UUID userId, String userEmail, String userName,
                    AuditAction action, String details, boolean success) {
        try {
            AuditLog entry = AuditLog.builder()
                    .accountId(accountId)
                    .userId(userId)
                    .userEmail(userEmail)
                    .userName(userName)
                    .action(action)
                    .details(details)
                    .ipAddress(extractIp())
                    .timestamp(LocalDateTime.now())
                    .success(success)
                    .build();
            auditLogRepository.save(entry);
        } catch (Exception ignored) {
            // log failure must never break the main request
        }
    }

    // ── IP extraction ─────────────────────────────────────────────────────────

    private String extractIp() {
        try {
            ServletRequestAttributes attrs =
                    (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
            HttpServletRequest req = attrs.getRequest();

            // Suporte a proxies reversos (Nginx, load balancers)
            String forwarded = req.getHeader("X-Forwarded-For");
            if (forwarded != null && !forwarded.isBlank()) {
                return forwarded.split(",")[0].trim();
            }

            String realIp = req.getHeader("X-Real-IP");
            if (realIp != null && !realIp.isBlank()) {
                return realIp.trim();
            }

            return req.getRemoteAddr();
        } catch (Exception e) {
            return null;
        }
    }
}
