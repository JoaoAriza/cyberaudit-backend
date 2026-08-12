package com.joao.cyberaudit.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.joao.cyberaudit.dto.SubscriptionDto;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.service.BillingService;
import com.joao.cyberaudit.service.ClientIpResolver;
import com.joao.cyberaudit.service.MercadoPagoService;
import com.joao.cyberaudit.service.RateLimitService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;

/**
 * Endpoints de billing/assinatura.
 * /billing/subscribe|subscription|cancel → autenticados (regra /billing/** no SecurityConfig).
 * /billing/webhook → público (Mercado Pago), mas confirma tudo contra a API do MP e valida
 * a assinatura x-signature quando o secret está configurado.
 */
@RestController
public class BillingController {

    /** Teto de notificações aceitas por minuto e por IP. O MP real fica muito abaixo disso. */
    private static final int WEBHOOK_MAX_PER_MINUTE = 60;

    private final BillingService     billingService;
    private final MercadoPagoService mercadoPagoService;
    private final RateLimitService   rateLimitService;
    private final ObjectMapper       mapper;
    private final ClientIpResolver   clientIpResolver;

    @Value("${mp.webhook-secret:}")
    private String webhookSecret;

    public BillingController(BillingService billingService,
                             MercadoPagoService mercadoPagoService,
                             RateLimitService rateLimitService,
                             ObjectMapper mapper,
                             ClientIpResolver clientIpResolver) {
        this.billingService     = billingService;
        this.mercadoPagoService = mercadoPagoService;
        this.rateLimitService   = rateLimitService;
        this.mapper             = mapper;
        this.clientIpResolver   = clientIpResolver;
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
        // Endpoint público que dispara uma chamada de saída à API do MP por notificação
        // aceita. Sem teto, um laço de curl vira flood na nossa cota do Mercado Pago.
        if (!rateLimitService.allow("mp-webhook:" + clientIpResolver.resolve(request),
                WEBHOOK_MAX_PER_MINUTE, 60_000)) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body("rate limited");
        }
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

    /**
     * Valida o x-signature do MP.
     *
     * Sem secret configurado a validação era simplesmente pulada — inclusive em
     * produção, onde esquecer `MP_WEBHOOK_SECRET` deixava o endpoint aberto para
     * qualquer um mandar notificação. Agora só pula quando o Mercado Pago não está
     * integrado de fato (sem `MP_ACCESS_TOKEN`, ou seja, dev/sandbox sem dinheiro
     * envolvido); com o MP ativo e sem secret, rejeita.
     */
    private boolean verifySignature(HttpServletRequest request, String dataId) {
        if (webhookSecret == null || webhookSecret.isBlank()) {
            if (mercadoPagoService.isConfigured()) {
                System.err.println("[BillingWebhook] MP_ACCESS_TOKEN está configurado mas "
                        + "MP_WEBHOOK_SECRET não — notificação recusada. Defina o secret.");
                return false;
            }
            return true; // sem integração real: nada a proteger
        }
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
            // Comparação em tempo constante — não vazar por timing quanto do HMAC bateu.
            return MessageDigest.isEqual(
                    HexFormat.of().formatHex(hash).getBytes(StandardCharsets.UTF_8),
                    v1.toLowerCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            return false;
        }
    }

    private static String firstNonBlank(String... vals) {
        for (String v : vals) if (v != null && !v.isBlank()) return v;
        return null;
    }
}
