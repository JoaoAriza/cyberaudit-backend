package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.HostHeaderFinding;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

@Service
public class HostHeaderService {

    /**
     * Valor injetado — suficientemente específico para evitar FPs.
     * Não é um domínio real, logo qualquer reflexão é confirmada.
     */
    private static final String PROBE_VALUE = "cyberaudit-probe-7x3k.invalid";

    /**
     * Headers testados em ordem de prioridade.
     * Host vem primeiro porque é o vetor mais impactante.
     * Os demais são frequentemente usados por proxies/CDNs.
     */
    private static final List<String> PROBE_HEADERS = List.of(
            "Host",
            "X-Forwarded-Host",
            "X-Host",
            "X-Forwarded-Server",
            "X-Original-Host"
    );

    private final MessageCatalog catalog;

    public HostHeaderService(MessageCatalog catalog) {
        this.catalog = catalog;
    }

    private final HttpClient client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(6))
            .build();

    /**
     * Testa Host Header Injection na URL base do alvo.
     * Executa em scan passivo e ativo — não depende de query params.
     *
     * @param targetUrl  URL do alvo (sem query string obrigatória)
     * @return lista de findings (normalmente 0 ou poucos — 1 por header vulnerável)
     */
    public List<HostHeaderFinding> scan(String targetUrl) {
        List<HostHeaderFinding> findings = new ArrayList<>();
        if (targetUrl == null || targetUrl.isBlank()) return findings;

        // Extrai apenas o base URL (sem query string) para minimizar variáveis
        String base = stripQuery(targetUrl);

        for (String header : PROBE_HEADERS) {
            HostHeaderFinding finding = probeHeader(base, header);
            if (finding != null) findings.add(finding);
        }

        return findings;
    }

    private HostHeaderFinding probeHeader(String url, String headerName) {
        try {
            HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(url))
                    .GET()
                    .timeout(Duration.ofSeconds(10))
                    .header("User-Agent", ScannerHttp.USER_AGENT)
                    .header("Accept", "text/html,application/xhtml+xml,*/*");

            // Para o header "Host", sobrescrevemos o header padrão.
            // Para os demais, adicionamos normalmente.
            if ("Host".equalsIgnoreCase(headerName)) {
                builder.header("Host", PROBE_VALUE);
            } else {
                builder.header(headerName, PROBE_VALUE);
            }

            HttpResponse<String> resp = client.send(builder.build(),
                    ScannerHttp.limitedString());

            String body  = resp.body() == null ? "" : resp.body();
            String lower = body.toLowerCase(Locale.ROOT);
            String probe = PROBE_VALUE.toLowerCase(Locale.ROOT);

            // 1. Reflexão no header Location
            String location = resp.headers().firstValue("location").orElse(null);
            if (location != null && location.toLowerCase(Locale.ROOT).contains(probe)) {
                return HostHeaderFinding.builder()
                        .injectedHeader(headerName)
                        .injectedValue(PROBE_VALUE)
                        .reflectionPoint("LOCATION")
                        .evidence("Location: " + truncate(location, 120))
                        .severity("HIGH")
                        .build();
            }

            // 2. Reflexão no Set-Cookie (domain poisoning)
            List<String> cookies = resp.headers().allValues("set-cookie");
            for (String cookie : cookies) {
                if (cookie.toLowerCase(Locale.ROOT).contains(probe)) {
                    return HostHeaderFinding.builder()
                            .injectedHeader(headerName)
                            .injectedValue(PROBE_VALUE)
                            .reflectionPoint("SET_COOKIE")
                            .evidence("Set-Cookie: " + truncate(cookie, 120))
                            .severity("HIGH")
                            .build();
                }
            }

            // 3. Reflexão no body HTML — informativo (LOW), não explorável por si só.
            // Refletir o Host no body é comum e benigno (canonical, og:url). Os vetores
            // exploráveis são Location e Set-Cookie, tratados acima.
            int idx = lower.indexOf(probe);
            if (idx >= 0) {
                int start = Math.max(0, idx - 20);
                int end   = Math.min(body.length(), idx + 80);
                String snippet = body.substring(start, end)
                        .replaceAll("[\\r\\n\\t]+", " ").trim();
                return HostHeaderFinding.builder()
                        .injectedHeader(headerName)
                        .injectedValue(PROBE_VALUE)
                        .reflectionPoint("BODY")
                        .evidence(catalog.evidence("HOST_HEADER_BODY", snippet))
                        .severity("LOW")
                        .build();
            }

        } catch (Exception ignored) {}

        return null;
    }

    private String stripQuery(String url) {
        int q = url.indexOf('?');
        return q >= 0 ? url.substring(0, q) : url;
    }

    private String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
