package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.OpenRedirectFinding;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

@Service
public class OpenRedirectService {

    /**
     * Domínio externo controlado usado como payload.
     * Se o servidor redirecionar para ele, confirmamos a vulnerabilidade.
     * Não usamos um domínio real para não causar tráfego indesejado.
     */
    private static final String PROBE_DOMAIN = "https://open-redirect-probe.cyberaudit.io";

    /**
     * Parâmetros comuns que costumam receber URLs de redirect.
     * Ordem importa — os mais comuns primeiro.
     */
    private static final List<String> REDIRECT_PARAMS = List.of(
            "redirect", "redirect_to", "redirect_url",
            "url", "next", "return", "return_url",
            "returnTo", "goto", "destination",
            "continue", "target", "redir",
            "forward", "location", "link"
    );

    /**
     * Dois formatos de payload para cobrir diferentes implementações:
     * 1. URL completa
     * 2. URL com protocolo relativo (//domain)
     */
    private static final List<String> PAYLOADS = List.of(
            PROBE_DOMAIN,
            "//" + "open-redirect-probe.cyberaudit.io"
    );

    private final HttpClient client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    /**
     * Testa open redirect apenas se a URL já tem parâmetros (superfície detectada)
     * OU testa parâmetros comuns na raiz do site.
     *
     * Modo passivo: só testa se já há query params na URL alvo.
     * Modo ativo: testa parâmetros comuns mesmo sem superfície detectada.
     */
    public List<OpenRedirectFinding> scan(String targetUrl, boolean activeMode) {
        List<OpenRedirectFinding> findings = new ArrayList<>();

        if (activeMode) {
            String base = extractBase(targetUrl);
            if (base == null) return findings;

            for (String param : REDIRECT_PARAMS) {
                for (String payload : PAYLOADS) {
                    String testUrl = base + "/?" + param + "=" + encode(payload);
                    OpenRedirectFinding finding = probe(param, testUrl);
                    if (finding != null) {
                        findings.add(finding);
                        break;
                    }
                }
            }
        } else if (targetUrl.contains("?")) {
            findings.addAll(testExistingParams(targetUrl));
        }

        return findings;
    }

    private List<OpenRedirectFinding> testExistingParams(String url) {
        List<OpenRedirectFinding> findings = new ArrayList<>();
        try {
            URI uri   = URI.create(url);
            String query = uri.getQuery();
            if (query == null) return findings;

            String base = url.substring(0, url.indexOf('?'));

            for (String part : query.split("&")) {
                String[] kv  = part.split("=", 2);
                String   key = kv[0];

                for (String payload : PAYLOADS) {
                    String testUrl = base + "?" + key + "=" + encode(payload);
                    OpenRedirectFinding finding = probe(key, testUrl);
                    if (finding != null) {
                        findings.add(finding);
                        break;
                    }
                }
            }
        } catch (Exception ignored) {}
        return findings;
    }

    private OpenRedirectFinding probe(String param, String testUrl) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(testUrl))
                    .GET()
                    .timeout(Duration.ofSeconds(6))
                    .header("User-Agent", "CyberAuditScanner/1.0")
                    .build();

            HttpResponse<Void> resp = client.send(
                    req, HttpResponse.BodyHandlers.discarding());

            int status = resp.statusCode();

            // Só nos interessa redirects (3xx)
            if (status < 300 || status >= 400) return null;

            String location = resp.headers()
                    .firstValue("location").orElse("");

            if (location.isBlank()) return null;

            boolean vulnerable = location.contains("open-redirect-probe.cyberaudit.io");

            if (!vulnerable) return null;

            return new OpenRedirectFinding(
                    param, testUrl, location, true, "HIGH"
            );

        } catch (Exception e) {
            return null;
        }
    }

    private String extractBase(String url) {
        try {
            URI uri  = URI.create(url);
            int port = uri.getPort();
            if (port > 0 && port != 80 && port != 443)
                return uri.getScheme() + "://" + uri.getHost() + ":" + port;
            return uri.getScheme() + "://" + uri.getHost();
        } catch (Exception e) {
            return null;
        }
    }

    private String encode(String value) {
        try {
            return java.net.URLEncoder.encode(value,
                    java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            return value;
        }
    }
}