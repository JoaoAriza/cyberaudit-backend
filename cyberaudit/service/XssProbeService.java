package com.joao.cyberaudit.service;

import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.UUID;

@Service
public class XssProbeService {

    private final HttpClient client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.ALWAYS)
            .connectTimeout(Duration.ofSeconds(8))
            .build();

    // Retorna true se o marcador voltar "cru" na resposta (suspeita de reflexão sem escape)
    public boolean reflectedMarkerAppears(String urlWithParams) {
        try {
            if (urlWithParams == null || !urlWithParams.contains("?")) return false;

            String marker = "xss_probe_" + UUID.randomUUID().toString().replace("-", "").substring(0, 10);
            String mutatedUrl = mutateFirstParamValue(urlWithParams, marker);

            HttpRequest req = HttpRequest.newBuilder(URI.create(mutatedUrl))
                    .GET()
                    .timeout(Duration.ofSeconds(12))
                    .header("User-Agent", "CyberAuditScanner/1.0")
                    .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,/;q=0.8")
                    .build();

            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
            String body = resp.body() == null ? "" : resp.body();

            // Sinal forte: marcador aparece exatamente (sem encoding)
            if (body.contains(marker)) {
                // Se também aparecer encoded, pode ser que esteja escapando em algum contexto.
                // Mas a presença do marker cru já é um indicador forte.
                return true;
            }

            return false;

        } catch (Exception e) {
            return false;
        }
    }

    private String mutateFirstParamValue(String url, String marker) {
        int q = url.indexOf('?');
        String base = url.substring(0, q);
        String query = url.substring(q + 1);

        String[] parts = query.split("&", 2);
        String first = parts[0];
        String rest = (parts.length > 1) ? "&" + parts[1] : "";

        String[] kv = first.split("=", 2);
        String key = kv[0];
        String value = kv.length > 1 ? kv[1] : "";

        String decoded = URLDecoder.decode(value, StandardCharsets.UTF_8);
        String newValue = decoded + marker; // marcador inofensivo (sem <script>, sem tags)
        String encoded = URLEncoder.encode(newValue, StandardCharsets.UTF_8);

        return base + "?" + key + "=" + encoded + rest;
    }
}