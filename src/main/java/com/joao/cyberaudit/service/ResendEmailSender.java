package com.joao.cyberaudit.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.joao.cyberaudit.exception.EmailDeliveryException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Transporte pela API HTTP do Resend.
 *
 * <h2>Por que HTTP e não o SMTP do próprio Resend</h2>
 *
 * O Resend também aceita SMTP, e usá-lo seria só mudar configuração. Mas o
 * problema que motivou a troca pode ser exatamente bloqueio de porta de saída —
 * nunca confirmamos se o e-mail falhava por credencial ou por rede. Sair pela
 * 443 elimina essa variável: se HTTPS não funcionasse, nenhum scan funcionaria.
 *
 * De quebra, o erro vira JSON legível ("domain is not verified") em vez de um
 * código SMTP genérico, que é justamente o que faltava para diagnosticar.
 */
@Component
@ConditionalOnProperty(name = "mail.provider", havingValue = "resend")
public class ResendEmailSender implements EmailSender {

    private static final URI ENDPOINT = URI.create("https://api.resend.com/emails");

    private final HttpClient   http;
    private final ObjectMapper mapper;

    @Value("${resend.api-key:}")
    private String apiKey;

    public ResendEmailSender(ObjectMapper mapper) {
        this.mapper = mapper;
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    @Override
    public void send(String from, String to, String subject, String html) {
        if (apiKey == null || apiKey.isBlank()) {
            throw new EmailDeliveryException(
                    "RESEND_API_KEY não configurada (mail.provider=resend).");
        }

        String payload;
        try {
            ObjectNode body = mapper.createObjectNode();
            body.put("from", from);
            body.putArray("to").add(to);
            body.put("subject", subject);
            body.put("html", html);
            payload = mapper.writeValueAsString(body);
        } catch (RuntimeException | com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new EmailDeliveryException("Resend: falha ao montar o payload.", e);
        }

        try {
            HttpRequest req = HttpRequest.newBuilder(ENDPOINT)
                    .timeout(Duration.ofSeconds(15))
                    .header("Authorization", "Bearer " + apiKey)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(payload))
                    .build();

            HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());

            if (res.statusCode() < 200 || res.statusCode() >= 300) {
                // O corpo do Resend explica o motivo real (domínio não verificado,
                // chave inválida, destinatário recusado). Vai para a exceção porque
                // é o que torna a falha diagnosticável no log — o handler HTTP não
                // repassa isto ao usuário final.
                throw new EmailDeliveryException(
                        "Resend respondeu " + res.statusCode() + ": " + resumo(res.body()));
            }
        } catch (java.io.IOException e) {
            throw new EmailDeliveryException("Resend: falha de rede — " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new EmailDeliveryException("Resend: envio interrompido.", e);
        }
    }

    /** Evita despejar um corpo enorme no log em caso de resposta inesperada. */
    private String resumo(String body) {
        if (body == null || body.isBlank()) return "(sem corpo)";
        String limpo = body.replaceAll("\\s+", " ").trim();
        return limpo.length() > 300 ? limpo.substring(0, 300) + "…" : limpo;
    }
}
