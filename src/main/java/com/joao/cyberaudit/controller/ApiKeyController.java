package com.joao.cyberaudit.controller;

import com.joao.cyberaudit.dto.ApiKeyDto;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.AuditAction;
import com.joao.cyberaudit.model.ScanResult;
import com.joao.cyberaudit.service.ApiKeyService;
import com.joao.cyberaudit.service.AuditService;
import com.joao.cyberaudit.service.ScanOrchestrator;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api-keys")
public class ApiKeyController {

    private final ApiKeyService   apiKeyService;
    private final AuditService    auditService;
    private final ScanOrchestrator scanOrchestrator;

    public ApiKeyController(ApiKeyService apiKeyService,
                            AuditService auditService,
                            ScanOrchestrator scanOrchestrator) {
        this.apiKeyService    = apiKeyService;
        this.auditService     = auditService;
        this.scanOrchestrator = scanOrchestrator;
    }

    /** Lista todas as API keys da conta do usuário autenticado. */
    @GetMapping
    public List<ApiKeyDto> list(@AuthenticationPrincipal AppUser user) {
        return apiKeyService.list(user);
    }

    /**
     * Cria uma nova API key.
     * Body: { "name": "GitHub CI" }
     * Resposta inclui `plainKey` — exibido APENAS nesta resposta; não é recuperável depois.
     */
    @PostMapping
    public ResponseEntity<ApiKeyDto> create(
            @RequestBody Map<String, String> body,
            @AuthenticationPrincipal AppUser user) {

        String name = body.get("name");
        ApiKeyDto created = apiKeyService.create(name, user);
        auditService.log(user, AuditAction.API_KEY_CREATED, "name=" + name);
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    /** Revoga uma API key pelo ID. */
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> revoke(
            @PathVariable UUID id,
            @AuthenticationPrincipal AppUser user) {

        apiKeyService.revoke(id, user);
        auditService.log(user, AuditAction.API_KEY_REVOKED, "id=" + id);
        return ResponseEntity.noContent().build();
    }

    // ── Endpoint CI/CD ────────────────────────────────────────────────────────

    /**
     * Gate de qualidade para pipelines CI/CD.
     *
     * Executa um scan passivo e retorna:
     *   - HTTP 200  se score >= threshold (pipeline passa)
     *   - HTTP 422  se score <  threshold (pipeline falha)
     *
     * Autenticado via X-Api-Key header.
     *
     * Parâmetros:
     *   url       — URL alvo (obrigatório)
     *   threshold — score mínimo (0-100, padrão 70)
     *   active    — incluir checks ativos (padrão false; exige plano adequado)
     *
     * Exemplo:
     *   curl -H "X-Api-Key: ca_..." \
     *        "https://api.cyberaudit.io/api-keys/ci?url=example.com&threshold=80"
     */
    @GetMapping("/ci")
    public ResponseEntity<Map<String, Object>> ciGate(
            @RequestParam String url,
            @RequestParam(defaultValue = "70") int threshold,
            @RequestParam(defaultValue = "false") boolean active,
            @AuthenticationPrincipal AppUser user) {

        ScanResult result = scanOrchestrator.execute(url, active, user, false);
        int score = result.getScore() != null ? result.getScore().getScore() : 0;
        boolean pass = score >= threshold;

        Map<String, Object> body = Map.of(
                "url",       result.getFinalUrl() != null ? result.getFinalUrl() : url,
                "score",     score,
                "risk",      result.getScore() != null ? result.getScore().getRiskLevel() : "UNKNOWN",
                "threshold", threshold,
                "pass",      pass,
                "activeMode", result.isActiveMode(),
                "message",   pass
                        ? "Score " + score + " ≥ " + threshold + " — aprovado"
                        : "Score " + score + " < " + threshold + " — reprovado"
        );

        return ResponseEntity.status(pass ? HttpStatus.OK : HttpStatus.UNPROCESSABLE_ENTITY)
                .body(body);
    }
}
