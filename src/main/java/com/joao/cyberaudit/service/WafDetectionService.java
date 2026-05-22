package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.WafDetectionResult;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;

@Service
public class WafDetectionService {

    private final HttpClient client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NORMAL)
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    private static final List<String> WAF_PROBES = List.of(
            "?q=" + URLEncoder.encode("<script>alert(1)</script>", StandardCharsets.UTF_8),
            "?id=" + URLEncoder.encode("1' OR '1'='1", StandardCharsets.UTF_8),
            "?file=" + URLEncoder.encode("../../../../etc/passwd", StandardCharsets.UTF_8)
    );

    public WafDetectionResult scan(String targetUrl) {
        WafDetectionResult.WafDetectionResultBuilder b = WafDetectionResult.builder();

        try {
            // Passo 1 — headers da resposta normal
            Map<String, List<String>> normalHeaders = fetchHeaders(targetUrl);
            WafMatch headerMatch = detectFromHeaders(normalHeaders);

            if (headerMatch != null) {
                b.detected(true)
                        .provider(headerMatch.provider())
                        .confidence("HIGH")
                        .evidence("Header detectado: " + headerMatch.evidence());
            }

            // Passo 2 — verifica via: varnish (Fastly usa Varnish internamente)
            if (headerMatch == null) {
                String viaHeader = getHeader(normalHeaders, "via");
                if (viaHeader != null && viaHeader.toLowerCase().contains("varnish")) {
                    boolean hasFastlyHint = normalHeaders != null && (
                            normalHeaders.containsKey("x-served-by") ||
                                    normalHeaders.containsKey("x-cache-hits") ||
                                    normalHeaders.containsKey("x-timer")
                    );
                    b.detected(true)
                            .provider(hasFastlyHint ? "Fastly" : "Varnish Cache")
                            .confidence("HIGH")
                            .evidence("Via: " + viaHeader +
                                    (hasFastlyHint ? " + Fastly headers presentes" : ""));
                    headerMatch = new WafMatch("detected", "via varnish");
                }
            }

            // Passo 3 — probe com payload malicioso
            String probeUrl  = targetUrl + WAF_PROBES.get(0);
            int    probeCode = fetchStatusCode(probeUrl);

            String probeResponse;
            if (probeCode == 403 || probeCode == 406 ||
                    probeCode == 429 || probeCode == 503) {
                probeResponse = "BLOCKED";
                if (headerMatch == null) {
                    b.detected(true)
                            .confidence("MEDIUM")
                            .evidence("Payload bloqueado com HTTP " + probeCode);
                }
            } else if (probeCode >= 200 && probeCode < 500) {
                probeResponse = "PASSED";
            } else {
                probeResponse = "UNKNOWN";
            }

            b.probeResponse(probeResponse);

            // Passo 4 — Server header como fallback
            if (headerMatch == null && !probeResponse.equals("BLOCKED")) {
                String serverHeader = getHeader(normalHeaders, "server");
                String viaHeader    = getHeader(normalHeaders, "via");
                String serverWaf    = detectFromServerHeader(serverHeader, viaHeader);

                if (serverWaf != null) {
                    b.detected(true)
                            .provider(serverWaf)
                            .confidence("LOW")
                            .evidence("Server: " + serverHeader);
                } else {
                    b.detected(false)
                            .provider(null)
                            .confidence(null)
                            .evidence("Nenhum indicador de WAF encontrado");
                }
            }

        } catch (Exception e) {
            b.detected(false)
                    .evidence("Erro: " + e.getMessage());
        }

        WafDetectionResult result = b.build();
        result.setSummary(buildSummary(result));
        return result;
    }

    // ── Internos ──────────────────────────────────────────────────────────────

    private WafMatch detectFromHeaders(Map<String, List<String>> headers) {
        if (headers == null) return null;

        // Verifica Server header para Cloudflare antes dos outros
        String serverVal = getHeader(headers, "server");
        if (serverVal != null && serverVal.toLowerCase().contains("cloudflare")) {
            return new WafMatch("Cloudflare", "Server: " + serverVal);
        }

        // Ordem de prioridade — headers mais exclusivos primeiro
        List<Map.Entry<String, String>> ordered = List.of(
                // Cloudflare
                Map.entry("cf-ray",                "Cloudflare"),
                Map.entry("cf-cache-status",       "Cloudflare"),
                Map.entry("cf-placement",          "Cloudflare"),

                // AWS
                Map.entry("x-amz-cf-id",          "AWS CloudFront"),
                Map.entry("x-amz-cf-pop",         "AWS CloudFront"),
                Map.entry("x-amzn-requestid",     "AWS WAF"),

                // Akamai
                Map.entry("x-akamai-transformed", "Akamai"),
                Map.entry("akamai-grn",            "Akamai"),

                // Sucuri
                Map.entry("x-sucuri-id",           "Sucuri"),
                Map.entry("x-sucuri-cache",        "Sucuri"),

                // Imperva
                Map.entry("x-iinfo",               "Imperva"),
                Map.entry("incap-ses",             "Imperva"),
                Map.entry("visid-incap",           "Imperva"),

                // Vercel
                Map.entry("x-vercel-id",           "Vercel Edge"),

                // Azure
                Map.entry("x-azure-ref",           "Azure Front Door"),

                // GitHub
                Map.entry("x-github-request-id",  "GitHub Infrastructure"),

                // Google
                Map.entry("x-goog-request-id",    "Google Cloud"),

                // F5
                Map.entry("x-wa-info",             "F5 BIG-IP"),
                Map.entry("x-f5-request-id",       "F5 BIG-IP"),

                // Fastly — depois dos mais específicos
                Map.entry("x-fastly-request-id",  "Fastly"),
                Map.entry("fastly-restarts",       "Fastly"),
                Map.entry("x-served-by",           "Fastly"),
                Map.entry("x-cache-hits",          "Fastly"),
                Map.entry("x-timer",               "Fastly"),

                // Barracuda
                Map.entry("bni-persistence",       "Barracuda")
        );

        for (Map.Entry<String, String> fp : ordered) {
            String headerKey = fp.getKey();
            String provider  = fp.getValue();

            if (headers.containsKey(headerKey)) {
                String val = getHeader(headers, headerKey);
                return new WafMatch(provider, headerKey + ": " + val);
            }
        }
        return null;
    }

    private String detectFromServerHeader(String server, String via) {
        if (server == null && via == null) return null;
        String combined = ((server != null ? server : "") + " " +
                (via    != null ? via    : "")).toLowerCase();

        if (combined.contains("cloudflare")) return "Cloudflare";
        if (combined.contains("akamai"))     return "Akamai";
        if (combined.contains("sucuri"))     return "Sucuri";
        if (combined.contains("incapsula"))  return "Imperva";
        if (combined.contains("fastly"))     return "Fastly";
        return null;
    }

    private Map<String, List<String>> fetchHeaders(String url) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .GET()
                    .timeout(Duration.ofSeconds(4)) // ← era 8
                    .header("User-Agent", "Mozilla/5.0 CyberAuditScanner/1.0")
                    .build();
            HttpResponse<Void> resp = client.send(req, HttpResponse.BodyHandlers.discarding());
            return resp.headers().map();
        } catch (Exception e) { return null; }
    }

    private int fetchStatusCode(String url) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .GET()
                    .timeout(Duration.ofSeconds(4)) // ← era 8
                    .header("User-Agent", "Mozilla/5.0 CyberAuditScanner/1.0")
                    .build();
            HttpResponse<Void> resp = client.send(req, HttpResponse.BodyHandlers.discarding());
            return resp.statusCode();
        } catch (Exception e) { return -1; }
    }

    private String getHeader(Map<String, List<String>> headers, String name) {
        if (headers == null) return null;
        List<String> vals = headers.get(name.toLowerCase());
        return (vals != null && !vals.isEmpty()) ? vals.get(0) : null;
    }

    private String buildSummary(WafDetectionResult r) {
        if (!r.isDetected()) {
            return "WAF não confirmado via headers. O site pode usar proteção sem expor " +
                    "headers identificadores (prática comum em infraestruturas enterprise), " +
                    "ou pode não ter WAF. Probe com payload: " +
                    (r.getProbeResponse() != null ? r.getProbeResponse() : "N/A") + ".";
        }
        return switch (r.getConfidence() != null ? r.getConfidence() : "") {
            case "HIGH"   -> r.getProvider() + " detectado com alta confiança via header exclusivo. " +
                    "Camada de proteção ativa.";
            case "MEDIUM" -> "Possível WAF detectado — payloads maliciosos foram bloqueados.";
            case "LOW"    -> "Indício de " + r.getProvider() + " via Server header. " +
                    "Confirmação inconclusiva.";
            default       -> "WAF detectado: " + r.getProvider();
        };
    }

    private record WafMatch(String provider, String evidence) {}
}