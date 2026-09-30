package com.joao.cyberaudit.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.joao.cyberaudit.dto.PixCheckoutDto;
import com.joao.cyberaudit.dto.PlanCatalogDto;
import com.joao.cyberaudit.dto.SubscriptionDto;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.Plan;
import com.joao.cyberaudit.service.BillingService;
import com.joao.cyberaudit.service.ClientIpResolver;
import com.joao.cyberaudit.service.MercadoPagoService;
import com.joao.cyberaudit.service.PlanCatalogService;
import com.joao.cyberaudit.service.RateLimitService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Locale;
import java.util.List;
import java.util.Map;

/**
 * Endpoints de billing/assinatura.
 * /billing/subscription|cancel|checkout/** → autenticados (regra /billing/** no SecurityConfig).
 * /billing/checkout/card|pix → checkout transparente (tela própria do CyberAudit, sem
 * redirecionar pro MP) — ver {@link BillingService#startCardCheckout} e
 * {@link BillingService#startPixCheckout}.
 * /billing/plans → público: é o cardápio, e visitante precisa vê-lo antes de ter conta.
 * /billing/webhook → público (Mercado Pago), mas confirma tudo contra a API do MP e valida
 * a assinatura x-signature quando o secret está configurado. Trata dois topics:
 * preapproval (assinatura via cartão) e payment (Pix).
 */
@RestController
public class BillingController {

    /** Teto de notificações aceitas por minuto e por IP. O MP real fica muito abaixo disso. */
    private static final int WEBHOOK_MAX_PER_MINUTE = 60;

    /**
     * Teto de tentativas de checkout transparente por usuário/minuto. Baixo de
     * propósito: diferente do redirect pro MP, aqui o próprio backend aceita
     * cardTokenId/CPF direto — sem teto, vira superfície de teste de cartão roubado
     * (tentar vários tokens até um "authorized" passar).
     */
    private static final int CHECKOUT_MAX_PER_MINUTE = 5;

    private final BillingService     billingService;
    private final MercadoPagoService mercadoPagoService;
    private final RateLimitService   rateLimitService;
    private final ObjectMapper       mapper;
    private final ClientIpResolver   clientIpResolver;
    private final PlanCatalogService planCatalogService;

    @Value("${mp.webhook-secret:}")
    private String webhookSecret;

    public BillingController(BillingService billingService,
                             MercadoPagoService mercadoPagoService,
                             RateLimitService rateLimitService,
                             ObjectMapper mapper,
                             ClientIpResolver clientIpResolver,
                             PlanCatalogService planCatalogService) {
        this.billingService     = billingService;
        this.mercadoPagoService = mercadoPagoService;
        this.rateLimitService   = rateLimitService;
        this.mapper             = mapper;
        this.clientIpResolver   = clientIpResolver;
        this.planCatalogService = planCatalogService;
    }

    // ── Cardápio ─────────────────────────────────────────────────────────────────

    /**
     * Público: o cardápio aparece para visitante, antes de existir conta. Não diz
     * nada sobre quem chama — é a tabela de planos, igual para todo mundo.
     */
    @GetMapping("/billing/plans")
    public List<PlanCatalogDto> plans() {
        return planCatalogService.catalogo();
    }

    // ── Checkout transparente (tela própria, sem redirecionamento) ────────────────

    /**
     * Body: {"plan":"PRO"|"ENTERPRISE" (opcional), "cardTokenId":"..."}.
     * cardTokenId vem do SDK do Mercado Pago no navegador (mp.cardForm) — este
     * endpoint nunca recebe número de cartão, CVV ou validade.
     */
    @PostMapping("/billing/checkout/card")
    public SubscriptionDto checkoutCard(@AuthenticationPrincipal AppUser caller,
                                        @RequestBody Map<String, String> body) {
        enforceCheckoutRateLimit(caller);
        Plan escolhido = parsePlan(body.get("plan"));
        return billingService.startCardCheckout(caller, escolhido, body.get("cardTokenId"));
    }

    /**
     * Body: {"plan":"PRO"|"ENTERPRISE" (opcional), "cpf":"..."}.
     * Devolve o QR code/copia-e-cola; o cliente confirma pagando no próprio app do
     * banco — o plano só é liberado quando o webhook confirmar o payment.
     */
    @PostMapping("/billing/checkout/pix")
    public PixCheckoutDto checkoutPix(@AuthenticationPrincipal AppUser caller,
                                      @RequestBody Map<String, String> body) {
        enforceCheckoutRateLimit(caller);
        Plan escolhido = parsePlan(body.get("plan"));
        return billingService.startPixCheckout(caller, escolhido, body.get("cpf"));
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

            // preapproval → assinatura via cartão (hospedado ou transparente).
            // payment    → Pix (cada ciclo é um payment novo, nunca um preapproval).
            if (dataId != null && type != null && type.contains("preapproval")) {
                billingService.handleWebhook(dataId);
            } else if (dataId != null && "payment".equals(type)) {
                billingService.handlePaymentWebhook(dataId);
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

    private Plan parsePlan(String bruto) {
        if (bruto == null || bruto.isBlank()) return null;
        try {
            return Plan.valueOf(bruto.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Plano inválido: " + bruto + ". Use PRO ou ENTERPRISE.");
        }
    }

    private void enforceCheckoutRateLimit(AppUser caller) {
        String key = "billing-checkout:" + caller.getId();
        if (!rateLimitService.allow(key, CHECKOUT_MAX_PER_MINUTE, 60_000)) {
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,
                    "Muitas tentativas de checkout. Aguarde um minuto e tente de novo.");
        }
    }
}
