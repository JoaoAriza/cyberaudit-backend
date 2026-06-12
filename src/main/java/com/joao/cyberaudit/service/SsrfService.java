package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.SsrfFinding;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

@Service
public class SsrfService {

    /**
     * Parametros tipicamente usados para passar URLs para o servidor.
     * Conservador: evita params genericos como "id", "q", "search".
     */
    private static final Set<String> SSRF_PARAMS = Set.of(
            "url", "uri", "webhook", "callback", "redirect", "endpoint",
            "target", "src", "source", "dest", "destination", "link",
            "fetch", "proxy", "feed", "site", "open", "continue",
            "return", "next", "service", "api", "request", "path"
    );

    /**
     * Payloads em ordem de prioridade.
     * { url_payload, indicator_type }
     */
    private static final List<String[]> PAYLOADS = List.of(
            new String[]{ "http://169.254.169.254/latest/meta-data/",    "AWS_METADATA" },
            new String[]{ "http://169.254.169.254/latest/meta-data/iam/","AWS_METADATA" },
            new String[]{ "http://169.254.169.254/",                     "AWS_METADATA" },
            new String[]{ "http://metadata.google.internal/computeMetadata/v1/", "GCP_METADATA" },
            new String[]{ "http://169.254.169.254/computeMetadata/v1/",  "GCP_METADATA" },
            new String[]{ "http://127.0.0.1/",                           "ERROR_DISCLOSURE" },
            new String[]{ "http://127.0.0.1:22/",                        "ERROR_DISCLOSURE" },
            new String[]{ "http://127.0.0.1:25/",                        "ERROR_DISCLOSURE" },
            new String[]{ "http://localhost/",                            "ERROR_DISCLOSURE" },
            new String[]{ "http://[::1]/",                                "ERROR_DISCLOSURE" }
    );

    /** Marcadores de metadata AWS na resposta */
    private static final List<String> AWS_MARKERS = List.of(
            "ami-", "instance-id", "local-ipv4", "security-credentials",
            "placement/", "public-hostname", "meta-data", "instance-type"
    );

    /** Marcadores de metadata GCP na resposta */
    private static final List<String> GCP_MARKERS = List.of(
            "project-id", "instance/", "service-accounts", "computeMetadata",
            "google-compute", "instance-id"
    );

    /**
     * Mensagens de erro que revelam tentativa de conexao interna.
     * Anti-FP: so conta se o erro menciona IPs/hosts internos especificos.
     */
    private static final List<String> ERROR_MARKERS = List.of(
            "econnrefused", "connection refused", "dial tcp 127",
            "dial tcp ::1", "failed to connect to 127", "failed to connect to localhost",
            "java.net.connectexception", "connection timed out to 127",
            "ssh-", "ssh_", "220 smtp", "220-smtp"   // banners de servicos locais
    );

    /** Regex para detectar redirecionamento para endereco interno no header Location */
    private static final Pattern INTERNAL_REDIRECT = Pattern.compile(
            "https?://(127\\.0\\.0\\.1|localhost|::1|0\\.0\\.0\\.0|169\\.254\\.169\\.254" +
            "|10\\.\\d+\\.\\d+\\.\\d+|172\\.(1[6-9]|2\\d|3[01])\\.\\d+\\.\\d+" +
            "|192\\.168\\.\\d+\\.\\d+)",
            Pattern.CASE_INSENSITIVE
    );

    private final HttpClient client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)  // interceptar redirects manualmente
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    /**
     * Testa SSRF nos parametros URL-like da query string.
     * So executa em scan ativo quando ha surface de input.
     */
    public List<SsrfFinding> scan(String urlWithParams) {
        List<SsrfFinding> findings = new ArrayList<>();
        if (urlWithParams == null || !urlWithParams.contains("?")) return findings;

        int q      = urlWithParams.indexOf('?');
        String base  = urlWithParams.substring(0, q);
        String query = urlWithParams.substring(q + 1);
        String[] pairs = query.split("&");

        for (String pair : pairs) {
            String[] kv  = pair.split("=", 2);
            String   key = kv[0].trim().toLowerCase(Locale.ROOT);
            if (!SSRF_PARAMS.contains(key)) continue;

            SsrfFinding finding = probeParam(base, query, kv[0], pairs);
            if (finding != null) findings.add(finding);
        }

        return findings;
    }

    private SsrfFinding probeParam(String base, String originalQuery,
                                    String paramName, String[] allPairs) {
        for (String[] payloadEntry : PAYLOADS) {
            String payloadUrl  = payloadEntry[0];
            String indicator   = payloadEntry[1];

            String mutatedQuery = replaceParamValue(allPairs, paramName, payloadUrl);
            String url = base + "?" + mutatedQuery;

            try {
                HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                        .GET()
                        .timeout(Duration.ofSeconds(8))
                        .header("User-Agent", "Mozilla/5.0 CyberAuditScanner/1.0")
                        .header("Accept", "text/html,application/json,*/*")
                        .build();

                HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                String body  = resp.body() == null ? "" : resp.body();
                String lower = body.toLowerCase(Locale.ROOT);

                // 1. Check for internal redirect
                String location = resp.headers().firstValue("location").orElse(null);
                if (location != null && INTERNAL_REDIRECT.matcher(location).find()) {
                    return SsrfFinding.builder()
                            .parameter(paramName)
                            .payload(payloadUrl)
                            .indicator("INTERNAL_REDIRECT")
                            .evidence("Location: " + truncate(location, 100))
                            .severity("CRITICAL")
                            .build();
                }

                // 2. Check for AWS metadata content
                if ("AWS_METADATA".equals(indicator)) {
                    String evidence = matchesMarkers(body, lower, AWS_MARKERS);
                    if (evidence != null) {
                        return SsrfFinding.builder()
                                .parameter(paramName)
                                .payload(payloadUrl)
                                .indicator("AWS_METADATA")
                                .evidence(evidence)
                                .severity("CRITICAL")
                                .build();
                    }
                }

                // 3. Check for GCP metadata content
                if ("GCP_METADATA".equals(indicator)) {
                    String evidence = matchesMarkers(body, lower, GCP_MARKERS);
                    if (evidence != null) {
                        return SsrfFinding.builder()
                                .parameter(paramName)
                                .payload(payloadUrl)
                                .indicator("GCP_METADATA")
                                .evidence(evidence)
                                .severity("CRITICAL")
                                .build();
                    }
                }

                // 4. Check for error-based disclosure
                if ("ERROR_DISCLOSURE".equals(indicator)) {
                    String evidence = matchesMarkers(body, lower, ERROR_MARKERS);
                    if (evidence != null) {
                        return SsrfFinding.builder()
                                .parameter(paramName)
                                .payload(payloadUrl)
                                .indicator("ERROR_DISCLOSURE")
                                .evidence(evidence)
                                .severity("CRITICAL")
                                .build();
                    }
                }

            } catch (Exception ignored) {}
        }
        return null;
    }

    /**
     * Verifica se o body contem algum dos marcadores.
     * Retorna snippet de evidencia ou null.
     */
    private String matchesMarkers(String body, String lower, List<String> markers) {
        for (String marker : markers) {
            int idx = lower.indexOf(marker.toLowerCase(Locale.ROOT));
            if (idx >= 0) {
                int start = Math.max(0, idx - 10);
                int end   = Math.min(body.length(), idx + 80);
                return body.substring(start, end).replaceAll("[\\r\\n\\t]+", " ").trim();
            }
        }
        return null;
    }

    private String replaceParamValue(String[] pairs, String targetKey, String newValue) {
        StringBuilder sb = new StringBuilder();
        for (String pair : pairs) {
            if (sb.length() > 0) sb.append('&');
            String[] kv = pair.split("=", 2);
            if (kv[0].equalsIgnoreCase(targetKey)) {
                sb.append(kv[0]).append('=')
                  .append(URLEncoder.encode(newValue, StandardCharsets.UTF_8));
            } else {
                sb.append(pair);
            }
        }
        return sb.toString();
    }

    private String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
