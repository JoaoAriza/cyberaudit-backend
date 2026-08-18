package com.joao.cyberaudit.controller;

import com.joao.cyberaudit.dto.FeedbackDto;
import com.joao.cyberaudit.dto.FeedbackReplyRequest;
import com.joao.cyberaudit.dto.FeedbackRequest;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.FeedbackStatus;
import com.joao.cyberaudit.service.FeedbackService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Endpoints de feedback (contestação de achados).
 *
 * Sem @RequestMapping de classe: as rotas /feedback/** caem em
 * {@code anyRequest().authenticated()} e as /admin/feedback/** herdam a regra
 * {@code /admin/** = hasAnyRole(OWNER, ADMIN)} do SecurityConfig.
 */
@RestController
public class FeedbackController {

    private final FeedbackService feedbackService;

    public FeedbackController(FeedbackService feedbackService) {
        this.feedbackService = feedbackService;
    }

    // ── Cliente ─────────────────────────────────────────────────────────────

    @PostMapping("/feedback")
    public ResponseEntity<FeedbackDto> submit(@RequestBody FeedbackRequest req,
                                              @AuthenticationPrincipal AppUser caller) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(feedbackService.submit(caller, req));
    }

    @GetMapping("/feedback/mine")
    public List<FeedbackDto> mine(@AuthenticationPrincipal AppUser caller) {
        return feedbackService.listMine(caller);
    }

    // ── Admin (OWNER/ADMIN, escopo da própria conta) ──────────────────────────

    @GetMapping("/admin/feedback")
    public List<FeedbackDto> adminList(@RequestParam(required = false) String status,
                                       @AuthenticationPrincipal AppUser caller) {
        return feedbackService.listForAdmin(caller, parseStatus(status));
    }

    @GetMapping("/admin/feedback/pending-count")
    public Map<String, Long> pendingCount(@AuthenticationPrincipal AppUser caller) {
        return Map.of("count", feedbackService.countPending(caller));
    }

    @PutMapping("/admin/feedback/{id}")
    public FeedbackDto reply(@PathVariable UUID id,
                             @RequestBody FeedbackReplyRequest req,
                             @AuthenticationPrincipal AppUser caller) {
        return feedbackService.reply(caller, id, req);
    }

    /**
     * Exclui uma contestação da fila, com justificativa obrigatória.
     *
     * POST e não DELETE porque a justificativa vai no corpo, e corpo em DELETE é
     * descartado por parte da infraestrutura no caminho (temos Cloudflare na
     * frente). Perder o corpo aqui significaria excluir sem motivo — justamente o
     * que este endpoint existe para impedir.
     */
    @PostMapping("/admin/feedback/{id}/delete")
    public FeedbackDto delete(@PathVariable UUID id,
                              @RequestBody Map<String, String> body,
                              @AuthenticationPrincipal AppUser caller) {
        return feedbackService.delete(caller, id, body.get("reason"));
    }

    private FeedbackStatus parseStatus(String s) {
        if (s == null || s.isBlank()) return null;
        try { return FeedbackStatus.valueOf(s.toUpperCase()); }
        catch (IllegalArgumentException e) { return null; }
    }
}
