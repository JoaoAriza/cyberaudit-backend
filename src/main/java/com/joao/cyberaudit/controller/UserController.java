package com.joao.cyberaudit.controller;

import com.joao.cyberaudit.dto.TimeZoneRequest;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.AuditAction;
import com.joao.cyberaudit.service.AccountDeletionService;
import com.joao.cyberaudit.service.AuditService;
import com.joao.cyberaudit.service.DataExportService;
import com.joao.cyberaudit.service.UserTimeZoneService;
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
    private final UserTimeZoneService    userTimeZoneService;

    public UserController(DataExportService dataExportService,
                          AccountDeletionService accountDeletionService,
                          AuditService auditService,
                          UserTimeZoneService userTimeZoneService) {
        this.dataExportService      = dataExportService;
        this.accountDeletionService = accountDeletionService;
        this.auditService           = auditService;
        this.userTimeZoneService    = userTimeZoneService;
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

    // ── Fuso horário ──────────────────────────────────────────────────────────

    /**
     * Grava o fuso do usuário, usado pelo que o servidor gera sem navegador na
     * frente: hora do agendamento, carimbo do PDF, corte de dia dos filtros.
     *
     * Endpoint único para as duas origens de propósito. A interface chama com
     * {@code manual: false} logo depois de autenticar, mandando o fuso que o
     * navegador detectou; o seletor do perfil chama com {@code manual: true}. O
     * serviço é que decide quem sobrepõe quem — a alternativa era capturar o fuso
     * no login, no registro, na verificação de 2FA e no aceite de convite, quatro
     * caminhos que ainda deixariam de fora a sessão retomada por token guardado.
     */
    @PutMapping("/timezone")
    public ResponseEntity<Map<String, Object>> setTimezone(@AuthenticationPrincipal AppUser user,
                                                           @RequestBody TimeZoneRequest req) {
        AppUser salvo = userTimeZoneService.definir(user, req.getTimezone(), req.isManual());
        return ResponseEntity.ok(estado(salvo));
    }

    /** Volta a seguir o navegador. */
    @DeleteMapping("/timezone")
    public ResponseEntity<Map<String, Object>> clearTimezone(@AuthenticationPrincipal AppUser user) {
        return ResponseEntity.ok(estado(userTimeZoneService.automatico(user)));
    }

    private static Map<String, Object> estado(AppUser user) {
        // Map.of não aceita valor nulo, e nulo aqui é estado legítimo: "siga o
        // navegador". Vira string vazia na resposta.
        return Map.of(
                "timezone", user.getTimezone() == null ? "" : user.getTimezone(),
                "timezoneManual", user.isTimezoneManual());
    }
}
