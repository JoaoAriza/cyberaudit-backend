package com.joao.cyberaudit.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
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
 * Cliente REST das APIs de Assinaturas (preapproval) e Pagamentos (payments) do Mercado Pago.
 * Documentação: https://www.mercadopago.com.br/developers/pt/reference/subscriptions/_preapproval/post
 *              https://www.mercadopago.com.br/developers/pt/reference/payments/_payments/post
 *
 * Nunca vê número de cartão, CVV ou validade — só o {@code card_token_id} gerado
 * pelo SDK do MP no navegador do cliente (checkout transparente). Aqui só
 * criamos/consultamos/cancelamos assinatura e pagamento com o access token do
 * servidor.
 */
@Service
public class MercadoPagoService {

    private static final String BASE = "https://api.mercadopago.com";

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10)).build();
    private final ObjectMapper mapper;

    @Value("${mp.access-token:}")
    private String accessToken;

    /**
     * Só para o log de boot: o secret é USADO pelo {@code BillingController} ao
     * validar a assinatura do webhook. Aqui ele serve para dizer, junto da
     * credencial, se o webhook está protegido — sem isso, pagamento aprovado não
     * sobe de plano e o único sinal era um aviso que só aparecia quando o MP
     * mandava uma notificação.
     */
    @Value("${mp.webhook-secret:}")
    private String webhookSecret;

    public MercadoPagoService(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    public boolean isConfigured() {
        return accessToken != null && !accessToken.isBlank();
    }

    /**
     * Token sem espaço/quebra de linha nas pontas.
     *
     * Copiar a credencial do painel para a variável de ambiente arrasta espaço ou
     * newline com facilidade. O header sai malformado e o Mercado Pago responde
     * 401 — indistinguível de token errado, e sem pista nenhuma de que o problema
     * é um caractere invisível.
     */
    private String tokenLimpo() {
        return accessToken == null ? "" : accessToken.trim();
    }

    /**
     * Registra QUAL credencial está em uso, sem expor o segredo.
     *
     * Trocar a variável no painel e esquecer de reiniciar — ou editar o valor no
     * lugar errado — produz exatamente o mesmo 401 de um token inválido. Sem um
     * sinal no log, não há como distinguir "credencial errada" de "credencial
     * certa que não chegou até aqui", e a investigação vira tentativa e erro.
     *
     * Prefixo e tamanho bastam para reconhecer a credencial e não são segredo: o
     * prefixo é público por natureza (APP_USR-/TEST-) e o tamanho não ajuda a
     * adivinhar o resto.
     */
    @PostConstruct
    public void registrarCredencialEmUso() {
        String t = tokenLimpo();
        if (t.isEmpty()) {
            System.out.println("[MercadoPago] MP_ACCESS_TOKEN ausente — pagamentos desativados.");
            return;
        }
        String prefixo = t.length() >= 12 ? t.substring(0, 12) : t.substring(0, Math.min(4, t.length()));
        String ambiente = t.startsWith("TEST-") ? "TESTE" : t.startsWith("APP_USR-") ? "PRODUÇÃO" : "DESCONHECIDO";

        System.out.println("[MercadoPago] credencial em uso: " + prefixo + "… ("
                + t.length() + " caracteres, ambiente " + ambiente + ")");

        // Public Key tem cara de UUID logo após o prefixo e é bem mais curta que
        // o Access Token. Confundir as duas é o erro mais comum da integração.
        if (t.length() < 60) {
            System.err.println("[MercadoPago] ATENÇÃO: credencial curta demais para um Access Token. "
                    + "Confira se não é a Public Key — ela não autentica chamadas de servidor.");
        }

        // Estado do secret do webhook, positivo a cada boot: sem "ausência de aviso"
        // para interpretar. Sem ele, o BillingController recusa toda notificação do
        // MP e o pagamento aprovado não vira upgrade de plano.
        if (webhookSecret != null && !webhookSecret.isBlank()) {
            System.out.println("[MercadoPago] webhook secret: configurado.");
        } else {
            System.err.println("[MercadoPago] webhook secret: AUSENTE — o webhook recusa TODAS as "
                    + "notificações (401) e pagamento aprovado não sobe de plano. Defina MP_WEBHOOK_SECRET.");
        }
    }

    // ── Resultados ──────────────────────────────────────────────────────────────

    public record PreapprovalResult(String id, String status) {}

    /**
     * {@code amount} vem de {@code auto_recurring.transaction_amount} — o valor que o MP
     * de fato cobra. Serve para o backend conferir que a assinatura confirmada custa o
     * que a tabela de preços diz, em vez de confiar só no id do preapproval.
     */
    public record PreapprovalInfo(String id, String status, String externalReference,
                                  BigDecimal amount, String currency) {}

    /**
     * QR code e copia-e-cola vêm prontos da API — só exibidos, nunca reconstruídos
     * aqui (reconstruir o payload do Pix na mão é como se introduz cobrança errada
     * sem ninguém perceber até o cliente escanear).
     */
    public record PixPaymentResult(String id, String status, String qrCode,
                                   String qrCodeBase64, String ticketUrl) {}

    /**
     * {@code amount} vem de {@code transaction_amount} — o valor que o MP de fato
     * recebeu por este payment, para a mesma conferência que {@link PreapprovalInfo}
     * faz para assinatura via cartão.
     */
    public record PaymentInfo(String id, String status, String externalReference,
                              BigDecimal amount, String currency) {}

    // ── Operações ───────────────────────────────────────────────────────────────

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

    /**
     * Cria uma assinatura (preapproval) JÁ com o cartão tokenizado no cliente
     * (checkout transparente) — sem redirecionamento, {@code status} normalmente
     * vem "authorized" na hora. O upgrade de plano em si continua dependendo do
     * webhook (ver {@code BillingService.handleWebhook}), nunca desta resposta.
     *
     * {@code cardTokenId} é gerado no navegador pelo SDK do MP (mp.cardForm /
     * createCardToken) — este método nunca recebe número de cartão, CVV ou
     * validade, só o token de uso único.
     */
    public PreapprovalResult createPreapprovalWithCard(String reason, BigDecimal amount, String currency,
                                                       String payerEmail, String externalReference,
                                                       String backUrl, String cardTokenId) {
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
        body.put("card_token_id", cardTokenId);
        body.put("auto_recurring", autoRecurring);
        body.put("back_url", backUrl);
        body.put("status", "authorized");

        JsonNode json = send("POST", "/preapproval", body);
        return new PreapprovalResult(text(json, "id"), text(json, "status"));
    }

    /**
     * Cria um pagamento Pix único (não recorrente — ver {@link com.joao.cyberaudit.model.PaymentMethod#PIX}).
     * O QR code some da resposta se o cliente não pagar: o valor de retorno tem que
     * ser exibido/salvo na hora, não recuperado depois.
     *
     * @param cpf apenas dígitos — obrigatório pelo MP para identification.type=CPF no Brasil.
     */
    public PixPaymentResult createPixPayment(BigDecimal amount, String currency, String payerEmail,
                                             String cpf, String description, String externalReference) {
        requireConfigured();

        Map<String, Object> identification = new LinkedHashMap<>();
        identification.put("type", "CPF");
        identification.put("number", cpf);

        Map<String, Object> payer = new LinkedHashMap<>();
        payer.put("email", payerEmail);
        payer.put("identification", identification);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("transaction_amount", amount);
        body.put("description", description);
        body.put("payment_method_id", "pix");
        body.put("external_reference", externalReference);
        body.put("payer", payer);

        // Chave nova a cada chamada — NUNCA derivada de algo estável como o accountId:
        // isso faria o pagamento do mês seguinte ser tratado como retry do anterior
        // e o MP devolveria o Pix (já vencido) de um mês atrás em vez de criar um novo.
        JsonNode json = send("POST", "/v1/payments", body, java.util.UUID.randomUUID().toString());
        JsonNode poi  = json != null ? json.get("point_of_interaction") : null;
        JsonNode data = poi  != null ? poi.get("transaction_data")      : null;

        return new PixPaymentResult(
                text(json, "id"),
                text(json, "status"),
                text(data, "qr_code"),
                text(data, "qr_code_base64"),
                text(data, "ticket_url"));
    }

    /**
     * Consulta um payment (usado pelo webhook de Pix — fonte da verdade é sempre
     * esta chamada, nunca o corpo da notificação).
     */
    public PaymentInfo getPayment(String id) {
        requireConfigured();
        JsonNode json = send("GET", "/v1/payments/" + id, null);
        return new PaymentInfo(
                text(json, "id"),
                text(json, "status"),
                text(json, "external_reference"),
                decimal(json, "transaction_amount"),
                text(json, "currency_id"));
    }

    // ── Interno ─────────────────────────────────────────────────────────────────

    private JsonNode send(String method, String path, Object body) {
        return send(method, path, body, null);
    }

    /**
     * @param idempotencyKey enviado como {@code X-Idempotency-Key} quando presente —
     *                       o MP usa isso para não duplicar a operação se a requisição
     *                       for reenviada (retry de rede). Só faz sentido em POST que
     *                       cria algo (payment, preapproval); null nos demais.
     */
    private JsonNode send(String method, String path, Object body, String idempotencyKey) {
        try {
            String payload = body != null ? mapper.writeValueAsString(body) : null;
            HttpRequest.Builder req = HttpRequest.newBuilder()
                    .uri(URI.create(BASE + path))
                    .timeout(Duration.ofSeconds(15))
                    .header("Authorization", "Bearer " + tokenLimpo())
                    .header("Content-Type", "application/json");
            if (idempotencyKey != null) {
                req.header("X-Idempotency-Key", idempotencyKey);
            }

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
