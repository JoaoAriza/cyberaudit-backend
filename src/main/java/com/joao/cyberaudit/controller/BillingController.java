package com.joao.cyberaudit.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.joao.cyberaudit.dto.SubscriptionDto;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.service.BillingService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.Map;

/**
 * Endpoints de billing/assinatura.
 * /billing/subscribe|subscription|cancel → autenticados (regra /billing/** no SecurityConfig).
 * /billing/webhook → público (Mercado Pago), mas confirma tudo contra a API do MP e valida
 * a assinatura x-signature quando o secret está configurado.
 */
@RestController
public class BillingController {

    private final BillingService billingService;
    private final ObjectMapper mapper;

    @Value("${mp.webhook-secret:}")
    private String webhookSecret;

    public BillingController(BillingService billingService, ObjectMapper mapper) {
        this.billingService = billingService;
        this.mapper = mapper;
    }

    // ── Cliente ──────────────────────────────────────────────────────────────────

    @PostMapping("/billing/subscribe")
    public Map<String, String> subscribe(@AuthenticationPrincipal AppUser caller) {
        return Map.of("initPoint", billingService.startSubscription(caller));
    }

    @GetMapping("/billing/subscription")
    public ResponseEntity<SubscriptionDto> current(@AuthenticationPrincipal AppUser caller) {
        SubscriptionDto dto = billingService.getSubscription(caller);
        return dto == null ? ResponseEntity.noContent().build() : ResponseEntity.ok(dto);
    }

    @PostMapping("/billing/cancel")
    public ResponseEntity<Void> cancel(@AuthenticationPrincipal AppUser caller) {
        billingService.cancelSubscription(caller);
        return ResponseEntity.noContent().build();
    }

    // ── Webhook do Mercado Pago ──────────────────────────────────────────────────

    @PostMapping("/billing/webhook")
    public ResponseEntity<String> webhook(@RequestBody(required = false) String rawBody,
                                          @RequestParam Map<String, String> params,
                                          HttpServletRequest request) {
        try {
            String type   = firstNonBlank(params.get("type"), params.get("topic"));
            String dataId = firstNonBlank(params.get("data.id"), params.get("id"));

            if (rawBody != null && !rawBody.isBlank()) {
                try {
                    JsonNode n = mapper.readTree(rawBody);
                    if (n.hasNonNull("type"))   type = n.get("type").asText();
                    if (type == null && n.hasNonNull("action")) type = n.get("action").asText();
                    JsonNode data = n.get("data");
                    if (data != null && data.hasNonNull("id")) dataId = data.get("id").asText();
                } catch (Exception ignored) { /* corpo não-JSON */ }
            }

            if (!verifySignature(request, dataId)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("invalid signature");
            }

            // Processa apenas notificações de assinatura (preapproval).
            if (type != null && type.contains("preapproval") && dataId != null) {
                billingService.handleWebhook(dataId);
            }
        } catch (Exception e) {
            // Nunca propaga — responde 200 para o MP não reenviar em loop; loga para diagnóstico.
            System.err.println("[BillingWebhook] erro ao processar: " + e.getMessage());
        }
        return ResponseEntity.ok("ok");
    }

    /** Valida x-signature do MP. Se o secret não está configurado, pula (ambiente sandbox). */
    private boolean verifySignature(HttpServletRequest request, String dataId) {
        if (webhookSecret == null || webhookSecret.isBlank()) return true;
        try {
            String sig       = request.getHeader("x-signature");
            String requestId = request.getHeader("x-request-id");
            if (sig == null) return false;

            String ts = null, v1 = null;
            for (String part : sig.split(",")) {
                String[] kv = part.split("=", 2);
                if (kv.length == 2) {
                    String k = kv[0].trim();
                    if (k.equals("ts")) ts = kv[1].trim();
                    else if (k.equals("v1")) v1 = kv[1].trim();
                }
            }
            if (ts == null || v1 == null) return false;

            String manifest = "id:" + (dataId != null ? dataId : "")
                    + ";request-id:" + (requestId != null ? requestId : "")
                    + ";ts:" + ts + ";";
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(webhookSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] hash = mac.doFinal(manifest.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash).equalsIgnoreCase(v1);
        } catch (Exception e) {
            return false;
        }
    }

    private static String firstNonBlank(String... vals) {
        for (String v : vals) if (v != null && !v.isBlank()) return v;
        return null;
    }
}
