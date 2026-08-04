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
            .followRedirects(HttpClient.Redirect.NEVER)  // redirects seguidos por ScannerHttp.sendFollowingSafely (revalida cada hop)
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
                    .header("User-Agent", ScannerHttp.USER_AGENT)
                    .header("Accept", "text/html,application/xhtml+xml")
                    .build();

            HttpResponse<String> resp =
                    ScannerHttp.sendFollowingSafely(client, req, ScannerHttp.limitedString());
            String body = resp.body() == null ? "" : resp.body();

            // Passo 1: marker precisa aparecer no body
            // (se não reflete nada, não há superfície de XSS)
            if (!body.contains(marker)) return false;

            // Passo 2: localiza a janela de texto logo após o marker refletido.
            // Probe injetado: marker + "<\">". Os chars HTML-breaking (<, ", >) NÃO
            // ficam diretamente colados ao marker — ficam em posições marker+0, +1, +2.
            // Verificar body.contains(marker + "\"") nunca funciona porque o " está
            // na posição marker+1 (depois do <), não marker+0. A mesma falha vale para >.
            // Solução: extrair uma janela de 20 chars após o marker e inspecioná-la.
            // 20 chars cobre: raw "<\">", URL-encoded "%3C%22%3E", HTML "&lt;&quot;&gt;"
            // e JS-escaped "\u003c\u0022\u003e".
            int markerIdx   = body.indexOf(marker);
            int windowStart = markerIdx + marker.length();
            int windowEnd   = Math.min(windowStart + 20, body.length());
            String window   = body.substring(windowStart, windowEnd);

            boolean rawLt    = window.contains("<");
            boolean rawQuote = window.contains("\"");
            boolean rawGt    = window.contains(">");

            // Passo 3: verifica se estão escapados dentro da mesma janela
            boolean escapedLt    = window.contains("&lt;")   || window.contains("&#60;")  ||
                    window.contains("\\u003c");
            boolean escapedQuote = window.contains("&quot;")  || window.contains("&#34;")  ||
                    window.contains("\\u0022");
            boolean urlEncoded   = window.contains("%3C")     || window.contains("%22");

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