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

    /**
     * Detecta Reflected XSS verificando se caracteres HTML-breaking
     * aparecem sem encoding na resposta.
     *
     * Lógica:
     * 1. Injeta marker + "<\">" no parâmetro
     * 2. Verifica se o marker aparece no body (confirma reflexão)
     * 3. Verifica se os chars HTML aparecem RAW (não escapados)
     * 4. Se escapados como &lt;, &quot; etc → NÃO é XSS
     */
    public boolean reflectedMarkerAppears(String urlWithParams) {
        try {
            if (urlWithParams == null || !urlWithParams.contains("?")) return false;

            String id     = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
            String marker = "cyberaudit" + id;

            // Probe com caracteres HTML-breaking após o marker único
            // "<\">" permite detectar se o site escapa corretamente
            String probe      = marker + "<\">";
            String mutatedUrl = mutateFirstParamValue(urlWithParams, probe);

            HttpRequest req = HttpRequest.newBuilder(URI.create(mutatedUrl))
                    .GET()
                    .timeout(Duration.ofSeconds(12))
                    .header("User-Agent", "Mozilla/5.0 CyberAuditScanner/1.0")
                    .header("Accept", "text/html,application/xhtml+xml")
                    .build();

            HttpResponse<String> resp =
                    client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            String body = resp.body() == null ? "" : resp.body();

            // Passo 1: marker precisa aparecer no body
            // (se não reflete nada, não há superfície de XSS)
            if (!body.contains(marker)) return false;

            // Passo 2: verifica se os chars HTML aparecem RAW (não escapados)
            // Se o site escapa corretamente, veremos &lt;, &quot;, %3C, %22, etc.
            boolean rawLt    = body.contains(marker + "<");
            boolean rawQuote = body.contains(marker + "\"");
            boolean rawGt    = body.contains(marker + ">");

            // Passo 3: verifica se estão escapados
            boolean escapedLt    = body.contains(marker + "&lt;")  ||
                    body.contains(marker + "&#60;") ||
                    body.contains(marker + "\\u003c");
            boolean escapedQuote = body.contains(marker + "&quot;") ||
                    body.contains(marker + "&#34;")  ||
                    body.contains(marker + "\\u0022");
            boolean urlEncoded   = body.contains(marker + "%3C") ||
                    body.contains(marker + "%22");

            // Só reporta se algum char HTML aparece RAW e não foi escapado
            boolean hasRawChars   = rawLt || rawQuote || rawGt;
            boolean properlyEscaped = escapedLt || escapedQuote || urlEncoded;

            return hasRawChars && !properlyEscaped;

        } catch (Exception e) {
            return false;
        }
    }

    private String mutateFirstParamValue(String url, String probe) {
        int q = url.indexOf('?');
        String base  = url.substring(0, q);
        String query = url.substring(q + 1);

        String[] parts = query.split("&", 2);
        String   first = parts[0];
        String   rest  = (parts.length > 1) ? "&" + parts[1] : "";

        String[] kv    = first.split("=", 2);
        String   key   = kv[0];
        String   value = kv.length > 1 ? kv[1] : "";

        String decoded = URLDecoder.decode(value, StandardCharsets.UTF_8);
        String newValue = decoded + probe;
        String encoded  = URLEncoder.encode(newValue, StandardCharsets.UTF_8);

        return base + "?" + key + "=" + encoded + rest;
    }
}