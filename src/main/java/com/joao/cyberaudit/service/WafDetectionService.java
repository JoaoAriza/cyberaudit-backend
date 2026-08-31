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
            .followRedirects(HttpClient.Redirect.NEVER)  // redirects seguidos por ScannerHttp.sendFollowingSafely (revalida cada hop)
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    private static final List<String> WAF_PROBES = List.of(
            "?q=" + URLEncoder.encode("<script>alert(1)</script>", StandardCharsets.UTF_8),
            "?id=" + URLEncoder.encode("1' OR '1'='1", StandardCharsets.UTF_8),
            "?file=" + URLEncoder.encode("../../../../etc/passwd", StandardCharsets.UTF_8)
    );

    private final MessageCatalog catalog;

    public WafDetectionService(MessageCatalog catalog) {
        this.catalog = catalog;
    }

    public WafDetectionResult scan(String targetUrl) {
        WafDetectionResult.WafDetectionResultBuilder b = WafDetectionResult.builder();

        try {
            // Passo 1 — resposta normal (headers + status como baseline)
            HttpResponse<Void> baseline = fetchResponse(targetUrl);
            Map<String, List<String>> normalHeaders = baseline != null ? baseline.headers().map() : null;
            int baselineCode = baseline != null ? baseline.statusCode() : -1;
            WafMatch headerMatch = detectFromHeaders(normalHeaders);

            if (headerMatch != null) {
                b.detected(true)
                        .provider(headerMatch.provider())
                        .category(headerMatch.category())
                        .confidence("HIGH")
                        .evidence(catalog.evidence("WAF_HEADER", headerMatch.evidence()));
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
                            .category("CDN")   // Varnish/Fastly = CDN, não WAF
                            .confidence("HIGH")
                            .evidence(hasFastlyHint
                                    ? catalog.evidence("WAF_VIA_FASTLY", viaHeader)
                                    : catalog.evidence("WAF_VIA", viaHeader));
                    headerMatch = new WafMatch("detected", "CDN", "via varnish");
                }
            }

            // Passo 3 — diferencial: payload malicioso vs requisições benignas.
            // Um 403/406 só é sinal de WAF se for ESPECÍFICO do payload. Comparamos com
            // o baseline (root sem query) e um controle benigno (query string inócua). Se
            // as benignas também são bloqueadas, o 403 não vem de inspeção de payload —
            // é auth, bloqueio de UA, geo-block ou erro genérico → NÃO é WAF.
            int    benignCode = fetchStatusCode(targetUrl + "?q=hello123");
            String probeUrl   = targetUrl + WAF_PROBES.get(0);
            int    probeCode  = fetchStatusCode(probeUrl);

            boolean baselineAllowed = isAllowed(baselineCode) && isAllowed(benignCode);
            boolean payloadBlocked  = probeCode == 403 || probeCode == 406;

            String probeResponse;
            if (payloadBlocked && baselineAllowed) {
                probeResponse = "BLOCKED";
                if (headerMatch == null) {
                    // Bloqueio específico do payload, sem header identificador —
                    // WAF sem fingerprint exposto.
                    b.detected(true)
                            .category("WAF")
                            .confidence("MEDIUM")
                            .evidence(catalog.evidence("WAF_PAYLOAD_BLOCKED",
                                    probeCode, baselineCode, benignCode));
                }
            } else if (probeCode == 403 || probeCode == 406
                    || probeCode == 429 || probeCode == 503) {
                // Bloqueio/erro não específico do payload (baseline também afetado ou
                // status ambíguo de rate-limit/indisponibilidade) → não é evidência de WAF.
                probeResponse = "INCONCLUSIVE";
            } else if (probeCode >= 200 && probeCode < 400) {
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
                            .category(resolveCategory(serverWaf))
                            .confidence("LOW")
                            .evidence("Server: " + serverHeader);
                } else {
                    b.detected(false)
                            .provider(null)
                            .confidence(null)
                            .evidence(catalog.evidence("WAF_NONE"));
                }
            }

        } catch (Exception e) {
            b.detected(false)
                    .evidence(catalog.evidence("WAF_ERROR", e.getMessage()));
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
            return new WafMatch("Cloudflare", "WAF", "Server: " + serverVal);
        }

        // Ordem de prioridade — headers mais exclusivos primeiro
        // Formato: header → "PROVIDER|CATEGORY"
        // CATEGORY: WAF = firewall real | CDN = entrega sem WAF | BOTH = CDN com WAF opcional
        List<Map.Entry<String, String>> ordered = List.of(
                // Cloudflare — WAF real
                Map.entry("cf-ray",                "Cloudflare|WAF"),
                Map.entry("cf-cache-status",       "Cloudflare|WAF"),
                Map.entry("cf-placement",          "Cloudflare|WAF"),

                // AWS CloudFront (CDN) vs AWS WAF (WAF real)
                Map.entry("x-amz-cf-id",          "AWS CloudFront|BOTH"),
                Map.entry("x-amz-cf-pop",         "AWS CloudFront|BOTH"),
                Map.entry("x-amzn-requestid",     "AWS WAF|WAF"),

                // Akamai — WAF real
                Map.entry("x-akamai-transformed", "Akamai|WAF"),
                Map.entry("akamai-grn",            "Akamai|WAF"),

                // Sucuri — WAF real
                Map.entry("x-sucuri-id",           "Sucuri|WAF"),
                Map.entry("x-sucuri-cache",        "Sucuri|WAF"),

                // Imperva — WAF real
                Map.entry("x-iinfo",               "Imperva|WAF"),
                Map.entry("incap-ses",             "Imperva|WAF"),
                Map.entry("visid-incap",           "Imperva|WAF"),

                // Vercel — hosting/CDN, sem WAF nativo
                Map.entry("x-vercel-id",           "Vercel Edge|CDN"),

                // Azure Front Door — CDN com WAF opcional (não garantido)
                Map.entry("x-azure-ref",           "Azure Front Door|BOTH"),

                // GitHub — infraestrutura de hosting, não WAF
                Map.entry("x-github-request-id",  "GitHub Infrastructure|CDN"),

                // Google Cloud — CDN/hosting, não WAF
                Map.entry("x-goog-request-id",    "Google Cloud|CDN"),

                // F5 BIG-IP — WAF real
                Map.entry("x-wa-info",             "F5 BIG-IP|WAF"),
                Map.entry("x-f5-request-id",       "F5 BIG-IP|WAF"),

                // Fastly — CDN, sem WAF nativo
                Map.entry("x-fastly-request-id",  "Fastly|CDN"),
                Map.entry("fastly-restarts",       "Fastly|CDN"),
                Map.entry("x-served-by",           "Fastly|CDN"),
                Map.entry("x-cache-hits",          "Fastly|CDN"),
                Map.entry("x-timer",               "Fastly|CDN"),

                // Barracuda — WAF real
                Map.entry("bni-persistence",       "Barracuda|WAF")
        );

        for (Map.Entry<String, String> fp : ordered) {
            String headerKey  = fp.getKey();
            String providerRaw = fp.getValue();  // "PROVIDER|CATEGORY"

            if (headers.containsKey(headerKey)) {
                String val      = getHeader(headers, headerKey);
                String[] parts  = providerRaw.split("\\|", 2);
                String provider = parts[0];
                String category = parts.length > 1 ? parts[1] : "WAF";
                return new WafMatch(provider, category, headerKey + ": " + val);
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

    private HttpResponse<Void> fetchResponse(String url) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .GET()
                    .timeout(Duration.ofSeconds(4))
                    .header("User-Agent", ScannerHttp.USER_AGENT)
                    .build();
            return ScannerHttp.sendFollowingSafely(client, req, HttpResponse.BodyHandlers.discarding());
        } catch (Exception e) { return null; }
    }

    /** Considera "permitido" status 2xx/3xx — usado para o controle benigno do diferencial. */
    private boolean isAllowed(int code) {
        return code >= 200 && code < 400;
    }

    private int fetchStatusCode(String url) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .GET()
                    .timeout(Duration.ofSeconds(4))
                    .header("User-Agent", ScannerHttp.USER_AGENT)
                    .build();
            HttpResponse<Void> resp = ScannerHttp.sendFollowingSafely(client, req, HttpResponse.BodyHandlers.discarding());
            return resp.statusCode();
        } catch (Exception e) { return -1; }
    }

    private String getHeader(Map<String, List<String>> headers, String name) {
        if (headers == null) return null;
        List<String> vals = headers.get(name.toLowerCase());
        return (vals != null && !vals.isEmpty()) ? vals.get(0) : null;
    }

    /** Visível ao teste: as seis frases de resumo só provam que resolvem se forem chamadas. */
    String buildSummary(WafDetectionResult r) {
        if (!r.isDetected()) {
            return catalog.desc("WAF_NOT_CONFIRMED",
                    r.getProbeResponse() != null ? r.getProbeResponse() : "N/A");
        }

        // O rótulo do tipo entra na CHAVE, não como argumento: fragmento traduzido
        // interpolado em frase traduzida é a armadilha que já escapou no verbo do
        // score no módulo Changes. Aqui cada combinação é uma frase inteira.
        String tipo = switch (r.getCategory() != null ? r.getCategory() : "") {
            case "CDN"  -> "CDN";
            case "BOTH" -> "BOTH";
            default     -> "WAF";
        };

        return switch (r.getConfidence() != null ? r.getConfidence() : "") {
            case "HIGH"   -> catalog.desc("WAF_HIGH_" + tipo, r.getProvider());
            case "MEDIUM" -> catalog.desc("WAF_MEDIUM");
            case "LOW"    -> catalog.desc("WAF_LOW", r.getProvider());
            default       -> catalog.desc("WAF_DETECTED_" + tipo, r.getProvider());
        };
    }

    /** Resolve a categoria de um provider identificado via Server header (fallback). */
    private String resolveCategory(String provider) {
        if (provider == null) return null;
        return switch (provider) {
            case "Cloudflare", "Akamai", "Sucuri", "Imperva" -> "WAF";
            case "Fastly" -> "CDN";
            default -> "WAF";
        };
    }

    private record WafMatch(String provider, String category, String evidence) {}
}