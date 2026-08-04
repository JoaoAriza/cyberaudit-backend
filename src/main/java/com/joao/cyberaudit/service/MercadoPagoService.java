package com.joao.cyberaudit.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.math.BigDecimal;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Cliente REST da API de Assinaturas (preapproval) do Mercado Pago.
 * Documentação: https://www.mercadopago.com.br/developers/pt/reference/subscriptions/_preapproval/post
 *
 * Não guarda nem manipula dados de cartão — o cliente paga no checkout hospedado do MP
 * (via init_point). Aqui só criamos/consultamos/cancelamos a assinatura com o access token.
 */
@Service
public class MercadoPagoService {

    private static final String BASE = "https://api.mercadopago.com";

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10)).build();
    private final ObjectMapper mapper;

    @Value("${mp.access-token:}")
    private String accessToken;

    public MercadoPagoService(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    public boolean isConfigured() {
        return accessToken != null && !accessToken.isBlank();
    }

    // ── Resultados ──────────────────────────────────────────────────────────────

    public record PreapprovalResult(String id, String initPoint, String status) {}

    /**
     * {@code amount} vem de {@code auto_recurring.transaction_amount} — o valor que o MP
     * de fato cobra. Serve para o backend conferir que a assinatura confirmada custa o
     * que a tabela de preços diz, em vez de confiar só no id do preapproval.
     */
    public record PreapprovalInfo(String id, String status, String externalReference,
                                  BigDecimal amount, String currency) {}

    // ── Operações ───────────────────────────────────────────────────────────────

    /** Cria uma assinatura (preapproval) sem cartão → retorna o init_point p/ redirecionar o cliente. */
    public PreapprovalResult createPreapproval(String reason, BigDecimal amount, String currency,
                                               String payerEmail, String externalReference, String backUrl) {
        requireConfigured();

        Map<String, Object> autoRecurring = new LinkedHashMap<>();
        autoRecurring.put("frequency", 1);
        autoRecurring.put("frequency_type", "months");
        autoRecurring.put("transaction_amount", amount);
        autoRecurring.put("currency_id", currency);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("reason", reason);
        body.put("external_reference", externalReference);
        body.put("payer_email", payerEmail);
        body.put("auto_recurring", autoRecurring);
        body.put("back_url", backUrl);
        body.put("status", "pending");

        JsonNode json = send("POST", "/preapproval", body);
        return new PreapprovalResult(
                text(json, "id"),
                text(json, "init_point"),
                text(json, "status"));
    }

    public PreapprovalInfo getPreapproval(String id) {
        requireConfigured();
        JsonNode json = send("GET", "/preapproval/" + id, null);
        JsonNode recurring = json != null ? json.get("auto_recurring") : null;
        return new PreapprovalInfo(
                text(json, "id"),
                text(json, "status"),
                text(json, "external_reference"),
                decimal(recurring, "transaction_amount"),
                text(recurring, "currency_id"));
    }

    public void cancelPreapproval(String id) {
        requireConfigured();
        send("PUT", "/preapproval/" + id, Map.of("status", "cancelled"));
    }

    // ── Interno ─────────────────────────────────────────────────────────────────

    private JsonNode send(String method, String path, Object body) {
        try {
            String payload = body != null ? mapper.writeValueAsString(body) : null;
            HttpRequest.Builder req = HttpRequest.newBuilder()
                    .uri(URI.create(BASE + path))
                    .timeout(Duration.ofSeconds(15))
                    .header("Authorization", "Bearer " + accessToken)
                    .header("Content-Type", "application/json");

            HttpRequest.BodyPublisher pub = payload != null
                    ? HttpRequest.BodyPublishers.ofString(payload)
                    : HttpRequest.BodyPublishers.noBody();
            req.method(method, pub);

            HttpResponse<String> res = http.send(req.build(), ScannerHttp.limitedString());
            if (res.statusCode() >= 200 && res.statusCode() < 300) {
                return res.body() == null || res.body().isBlank()
                        ? mapper.createObjectNode()
                        : mapper.readTree(res.body());
            }
            String msg = extractError(res.body());
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY,
                    "Mercado Pago retornou " + res.statusCode() + (msg != null ? ": " + msg : ""));
        } catch (ResponseStatusException e) {
            throw e;
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY,
                    "Falha ao comunicar com o Mercado Pago: " + e.getMessage());
        }
    }

    private void requireConfigured() {
        if (!isConfigured()) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                    "Pagamentos indisponíveis: MP_ACCESS_TOKEN não configurado.");
        }
    }

    private String extractError(String body) {
        try {
            JsonNode n = mapper.readTree(body);
            if (n.hasNonNull("message")) return n.get("message").asText();
        } catch (Exception ignored) { /* corpo não-JSON */ }
        return body != null && body.length() < 300 ? body : null;
    }

    private String text(JsonNode n, String field) {
        return n != null && n.hasNonNull(field) ? n.get(field).asText() : null;
    }

    private BigDecimal decimal(JsonNode n, String field) {
        if (n == null || !n.hasNonNull(field)) return null;
        try {
            return n.get(field).decimalValue();
        } catch (Exception e) {
            return null;
        }
    }
}
