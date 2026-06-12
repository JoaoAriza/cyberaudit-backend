package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.SourceMapFinding;
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
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class SourceMapService {

    /**
     * Endpoints Actuator de alta severidade — expõem config, secrets, heap.
     */
    private static final List<String[]> ACTUATOR_HIGH = List.of(
            new String[]{ "/actuator/env",      "Spring Boot env — expõe variáveis de ambiente e segredos" },
            new String[]{ "/actuator/beans",     "Spring Boot beans — lista todos os beans da aplicação" },
            new String[]{ "/actuator/heapdump",  "Spring Boot heapdump — dump da heap da JVM" },
            new String[]{ "/actuator/threaddump","Spring Boot threaddump — threads da JVM" },
            new String[]{ "/actuator/loggers",   "Spring Boot loggers — configuração de logs" },
            new String[]{ "/actuator/mappings",  "Spring Boot mappings — lista todos os endpoints" }
    );

    /**
     * Endpoints Actuator de média severidade.
     */
    private static final List<String[]> ACTUATOR_MEDIUM = List.of(
            new String[]{ "/actuator",           "Spring Boot Actuator — endpoint raiz exposto" },
            new String[]{ "/actuator/info",      "Spring Boot info — metadados da aplicação" },
            new String[]{ "/actuator/metrics",   "Spring Boot metrics — métricas da aplicação" },
            new String[]{ "/actuator/conditions","Spring Boot conditions — diagnóstico de autoconfigure" }
    );

    /**
     * Endpoints de debug/profiler de frameworks web.
     */
    private static final List<String[]> DEBUG_ENDPOINTS = List.of(
            new String[]{ "/_profiler",               "Symfony Profiler exposto" },
            new String[]{ "/_profiler/phpinfo",        "Symfony phpinfo exposto" },
            new String[]{ "/debug/default/view",       "Yii2 Debug Toolbar exposto" },
            new String[]{ "/__debugbar/open",          "Laravel Debugbar exposto" },
            new String[]{ "/console",                  "Console interativo exposto" },
            new String[]{ "/telescope",                "Laravel Telescope exposto" },
            new String[]{ "/horizon",                  "Laravel Horizon exposto" },
            new String[]{ "/phpinfo.php",              "phpinfo() exposto" },
            new String[]{ "/info.php",                 "phpinfo() exposto" },
            new String[]{ "/server-info",              "Informação de servidor exposta" },
            new String[]{ "/.env",                     "Arquivo .env exposto" },
            new String[]{ "/config.json",              "Arquivo de config JSON exposto" },
            new String[]{ "/app/config.json",          "Arquivo de config da aplicação exposto" },
            new String[]{ "/rails/info/properties",    "Rails info exposto" },
            new String[]{ "/rails/info/routes",        "Rails routes exposto" }
    );

    /**
     * Regex para extrair src de tags <script> no HTML.
     */
    private static final Pattern SCRIPT_SRC = Pattern.compile(
            "<script[^>]+src=[\"']([^\"']+\\.js(?:\\?[^\"']*)?)[\"']",
            Pattern.CASE_INSENSITIVE
    );

    /**
     * Marcadores que confirmam que um endpoint Actuator/debug está acessível
     * (e não retornou 404 ou redirect para login).
     */
    private static final Set<String> ACTUATOR_MARKERS = Set.of(
            "\"status\"", "\"components\"", "\"beans\"", "\"contexts\"",
            "\"mappings\"", "\"dispatcherServlets\"", "\"_links\"",
            "\"loggers\"", "\"metrics\"", "\"info\""
    );

    private final HttpClient client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    /**
     * Executa scan de source maps e debug endpoints.
     * Roda no passive pool — não depende de query params.
     */
    public List<SourceMapFinding> scan(String targetUrl) {
        List<SourceMapFinding> findings = new ArrayList<>();
        if (targetUrl == null || targetUrl.isBlank()) return findings;

        String base = baseUrl(targetUrl);

        // 1. Source maps via headers e arquivos .map
        findings.addAll(scanSourceMaps(targetUrl, base));

        // 2. Spring Boot Actuator — alta severidade
        for (String[] entry : ACTUATOR_HIGH) {
            SourceMapFinding f = probeEndpoint(base + entry[0], "ACTUATOR", "HIGH", entry[1]);
            if (f != null) findings.add(f);
        }

        // 3. Spring Boot Actuator — média severidade
        for (String[] entry : ACTUATOR_MEDIUM) {
            SourceMapFinding f = probeEndpoint(base + entry[0], "ACTUATOR", "MEDIUM", entry[1]);
            if (f != null) findings.add(f);
        }

        // 4. Debug endpoints de outros frameworks
        for (String[] entry : DEBUG_ENDPOINTS) {
            SourceMapFinding f = probeEndpoint(base + entry[0], "DEBUG_ENDPOINT", "MEDIUM", entry[1]);
            if (f != null) findings.add(f);
        }

        return findings;
    }

    // ── Source Map Detection ─────────────────────────────────────────────────

    private List<SourceMapFinding> scanSourceMaps(String targetUrl, String base) {
        List<SourceMapFinding> findings = new ArrayList<>();

        String mainBody = fetch(targetUrl);
        if (mainBody == null) return findings;

        // Extrai URLs de scripts do HTML da página principal
        Matcher m = SCRIPT_SRC.matcher(mainBody);
        int checked = 0;
        while (m.find() && checked < 10) {
            String src = m.group(1);
            String jsUrl = resolveUrl(base, src);
            if (jsUrl == null) continue;
            checked++;

            // Verifica header SourceMap/X-SourceMap na resposta do JS
            SourceMapFinding headerFinding = checkSourceMapHeader(jsUrl);
            if (headerFinding != null) {
                findings.add(headerFinding);
                continue;
            }

            // Tenta acessar o arquivo .map diretamente
            String mapUrl = stripQueryAndFragment(jsUrl) + ".map";
            SourceMapFinding mapFinding = probeMapFile(mapUrl);
            if (mapFinding != null) findings.add(mapFinding);
        }

        return findings;
    }

    private SourceMapFinding checkSourceMapHeader(String jsUrl) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(jsUrl))
                    .GET()
                    .timeout(Duration.ofSeconds(8))
                    .header("User-Agent", "Mozilla/5.0 CyberAuditScanner/1.0")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));

            String sourceMap = resp.headers().firstValue("SourceMap")
                    .or(() -> resp.headers().firstValue("X-SourceMap"))
                    .orElse(null);

            if (sourceMap != null && !sourceMap.isBlank()) {
                return SourceMapFinding.builder()
                        .type("SOURCE_MAP_HEADER")
                        .url(jsUrl)
                        .evidence("SourceMap header: " + truncate(sourceMap, 80))
                        .severity("HIGH")
                        .build();
            }
        } catch (Exception ignored) {}
        return null;
    }

    private SourceMapFinding probeMapFile(String mapUrl) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(mapUrl))
                    .GET()
                    .timeout(Duration.ofSeconds(8))
                    .header("User-Agent", "Mozilla/5.0 CyberAuditScanner/1.0")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));

            if (resp.statusCode() != 200) return null;

            String body  = resp.body() == null ? "" : resp.body();
            String lower = body.toLowerCase(Locale.ROOT);

            // Confirma que é um source map real — deve conter campos JSON padrão
            if (lower.contains("\"sources\"") || lower.contains("\"mappings\"") || lower.contains("\"sourcecontent\"")) {
                return SourceMapFinding.builder()
                        .type("SOURCE_MAP_FILE")
                        .url(mapUrl)
                        .evidence(truncate(body.replaceAll("[\\r\\n\\t]+", " "), 100))
                        .severity("HIGH")
                        .build();
            }
        } catch (Exception ignored) {}
        return null;
    }

    // ── Actuator / Debug Endpoint Detection ──────────────────────────────────

    private SourceMapFinding probeEndpoint(String url, String type, String severity, String description) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .GET()
                    .timeout(Duration.ofSeconds(8))
                    .header("User-Agent", "Mozilla/5.0 CyberAuditScanner/1.0")
                    .header("Accept", "application/json,text/html,*/*")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));

            int status = resp.statusCode();
            if (status != 200 && status != 206) return null;

            String body  = resp.body() == null ? "" : resp.body();
            String lower = body.toLowerCase(Locale.ROOT);

            // Anti-FP: deve ter conteúdo relevante — não apenas uma página 200 genérica
            boolean confirmed = false;

            if ("ACTUATOR".equals(type)) {
                for (String marker : ACTUATOR_MARKERS) {
                    if (lower.contains(marker.toLowerCase(Locale.ROOT))) {
                        confirmed = true;
                        break;
                    }
                }
            } else {
                // Debug endpoints — 200 com conteúdo > 100 bytes é suficiente
                confirmed = body.length() > 100;
            }

            if (!confirmed) return null;

            return SourceMapFinding.builder()
                    .type(type)
                    .url(url)
                    .evidence(description + " (HTTP " + status + ")")
                    .severity(severity)
                    .build();

        } catch (Exception ignored) {}
        return null;
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private String fetch(String url) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .GET()
                    .timeout(Duration.ofSeconds(10))
                    .header("User-Agent", "Mozilla/5.0 CyberAuditScanner/1.0")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return resp.statusCode() == 200 ? resp.body() : null;
        } catch (Exception ignored) {
            return null;
        }
    }

    private String resolveUrl(String base, String src) {
        try {
            if (src.startsWith("http://") || src.startsWith("https://")) return src;
            if (src.startsWith("//")) return "https:" + src;
            if (src.startsWith("/")) return base + src;
            return base + "/" + src;
        } catch (Exception e) {
            return null;
        }
    }

    private String baseUrl(String url) {
        try {
            URI uri = URI.create(url);
            return uri.getScheme() + "://" + uri.getHost()
                    + (uri.getPort() != -1 ? ":" + uri.getPort() : "");
        } catch (Exception e) {
            return url;
        }
    }

    private String stripQueryAndFragment(String url) {
        int q = url.indexOf('?');
        if (q >= 0) url = url.substring(0, q);
        int h = url.indexOf('#');
        if (h >= 0) url = url.substring(0, h);
        return url;
    }

    private String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
