package com.joao.cyberaudit.controller;

import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.AuditAction;
import com.joao.cyberaudit.service.AccountDeletionService;
import com.joao.cyberaudit.service.AuditService;
import com.joao.cyberaudit.service.DataExportService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Endpoints de dados pessoais do usuário autenticado (LGPD).
 */
@RestController
@RequestMapping("/user")
public class UserController {

    private final DataExportService      dataExportService;
    private final AccountDeletionService accountDeletionService;
    private final AuditService           auditService;

    public UserController(DataExportService dataExportService,
                          AccountDeletionService accountDeletionService,
                          AuditService auditService) {
        this.dataExportService      = dataExportService;
        this.accountDeletionService = accountDeletionService;
        this.auditService           = auditService;
    }

    /**
     * LGPD Art. 18 — Portabilidade.
     * Retorna todos os dados pessoais do usuário em JSON.
     */
    @GetMapping("/data-export")
    public ResponseEntity<Map<String, Object>> exportData(
            @AuthenticationPrincipal AppUser user) {
        auditService.log(user, AuditAction.DATA_EXPORTED, null);
        return ResponseEntity.ok(dataExportService.exportUserData(user));
    }

    /**
     * LGPD Art. 18 — Direito ao esquecimento.
     * Remove a conta e os dados pessoais do usuário autenticado.
     *
     * Regras:
     * - Qualquer usuário pode excluir sua própria conta.
     * - OWNER só pode excluir se for o único usuário ativo da conta (evita conta órfã).
     */
    @DeleteMapping("/account")
    public ResponseEntity<Map<String, String>> deleteAccount(
            @AuthenticationPrincipal AppUser user) {

        // A ordem de remoção das dependências vive no AccountDeletionService —
        // errar essa ordem é o que fazia a exclusão estourar em violação de FK.
        var deleted = accountDeletionService.deleteOwnAccount(user);

        // Auditoria depois da exclusão, com a identidade preservada: o usuário
        // já não existe para ser referenciado.
        auditService.log(deleted.accountId(), null, deleted.email(), deleted.name(),
                AuditAction.ACCOUNT_DELETED,
                deleted.wasOwner() ? "OWNER self-deleted" : "user self-deleted", true);

        return ResponseEntity.ok(Map.of(
                "message", "Conta excluída com sucesso. Seus dados foram removidos."
        ));
    }
}
