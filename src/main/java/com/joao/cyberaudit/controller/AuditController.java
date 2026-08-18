package com.joao.cyberaudit.controller;

import com.joao.cyberaudit.dto.AuditLogDto;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.Role;
import com.joao.cyberaudit.repository.AuditLogRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/admin")
public class AuditController {

    private final AuditLogRepository auditLogRepository;
    private final com.joao.cyberaudit.service.PlanLimitService planLimitService;

    public AuditController(AuditLogRepository auditLogRepository,
                           com.joao.cyberaudit.service.PlanLimitService planLimitService) {
        this.auditLogRepository = auditLogRepository;
        this.planLimitService   = planLimitService;
    }

    /**
     * Retorna logs de auditoria paginados da conta do OWNER autenticado.
     *
     * @param page default 0
     * @param size default 50, max 200
     * @param from data inicial no formato yyyy-MM-dd (opcional)
     * @param to   data final   no formato yyyy-MM-dd (opcional)
     */
    @GetMapping("/audit-logs")
    public ResponseEntity<Map<String, Object>> listAuditLogs(
            @AuthenticationPrincipal AppUser caller,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size,
            @RequestParam(required = false) String from,
            @RequestParam(required = false) String to) {

        if (caller.getRole() != Role.OWNER && caller.getRole() != Role.ADMIN) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Acesso restrito a OWNER ou ADMIN.");
        }
        planLimitService.checkReportsModule(caller);

        UUID accountId = caller.getAccount() != null ? caller.getAccount().getId() : null;
        if (accountId == null) {
            return ResponseEntity.ok(Map.of(
                    "logs", List.of(),
                    "totalElements", 0L,
                    "totalPages", 0
            ));
        }

        Pageable pageable = PageRequest.of(page, Math.min(size, 200));

        Page<com.joao.cyberaudit.model.AuditLog> result;
        if (from != null || to != null) {
            LocalDateTime dtFrom = from != null
                    ? LocalDate.parse(from).atStartOfDay()
                    : LocalDateTime.MIN;
            LocalDateTime dtTo = to != null
                    ? LocalDate.parse(to).atTime(23, 59, 59)
                    : LocalDateTime.MAX;
            result = auditLogRepository
                    .findByAccountIdAndTimestampBetweenOrderByTimestampDesc(
                            accountId, dtFrom, dtTo, pageable);
        } else {
            result = auditLogRepository
                    .findByAccountIdOrderByTimestampDesc(accountId, pageable);
        }

        return ResponseEntity.ok(Map.of(
                "logs", result.getContent().stream().map(AuditLogDto::from).toList(),
                "totalElements", result.getTotalElements(),
                "totalPages", result.getTotalPages()
        ));
    }
}
