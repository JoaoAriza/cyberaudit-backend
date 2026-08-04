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
     *
     * Cada entrada carrega marcadores específicos da ferramenta (lowercase) usados
     * para confirmar a exposição. Anti-FP: SPAs respondem 200 + index.html para
     * qualquer rota, então sem um marcador real o achado é descartado.
     * Os arquivos (.env / config.json) têm markers vazios — validados por formato
     * em confirmsDebugContent().
     */
    private static final List<DebugTarget> DEBUG_ENDPOINTS = List.of(
            new DebugTarget("/_profiler",            "Symfony Profiler exposto",
                    List.of("sf-toolbar", "symfony profiler", "sf-profiler", "/_profiler/")),
            new DebugTarget("/_profiler/phpinfo",    "Symfony phpinfo exposto",
                    List.of("php version", "phpinfo()", "zend engine")),
            new DebugTarget("/debug/default/view",   "Yii2 Debug Toolbar exposto",
                    List.of("yii debugger", "/debug/default/")),
            new DebugTarget("/__debugbar/open",      "Laravel Debugbar exposto",
                    List.of("debugbar", "\"__meta\"", "\"php\":")),
            new DebugTarget("/console",              "Console interativo exposto",
                    List.of("werkzeug", "h2 console", "interactive console", "wsgi")),
            new DebugTarget("/telescope",            "Laravel Telescope exposto",
                    List.of("/vendor/telescope", "window.telescope", "laravel telescope")),
            new DebugTarget("/horizon",              "Laravel Horizon exposto",
                    List.of("/vendor/horizon", "window.horizon", "laravel horizon")),
            new DebugTarget("/phpinfo.php",          "phpinfo() exposto",
                    List.of("php version", "phpinfo()", "zend engine")),
            new DebugTarget("/info.php",             "phpinfo() exposto",
                    List.of("php version", "phpinfo()", "zend engine")),
            new DebugTarget("/server-info",          "Informação de servidor exposta",
                    List.of("apache server information", "server settings")),
            new DebugTarget("/.env",                 "Arquivo .env exposto",
                    List.of()),
            new DebugTarget("/config.json",          "Arquivo de config JSON exposto",
                    List.of()),
            new DebugTarget("/app/config.json",      "Arquivo de config da aplicação exposto",
                    List.of()),
            new DebugTarget("/rails/info/properties","Rails info exposto",
                    List.of("ruby version", "rails version", "rack version")),
            new DebugTarget("/rails/info/routes",    "Rails routes exposto",
                    List.of("controller#action", "uri pattern"))
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
        for (DebugTarget entry : DEBUG_ENDPOINTS) {
            SourceMapFinding f = probeDebugEndpoint(base + entry.path(), entry);
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
                    .header("User-Agent", ScannerHttp.USER_AGENT)
                    .build();
            HttpResponse<String> resp = client.send(req, ScannerHttp.limitedString());

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
                    .header("User-Agent", ScannerHttp.USER_AGENT)
                    .build();
            HttpResponse<String> resp = client.send(req, ScannerHttp.limitedString());

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
                    .header("User-Agent", ScannerHttp.USER_AGENT)
                    .header("Accept", "application/json,text/html,*/*")
                    .build();
            HttpResponse<String> resp = client.send(req, ScannerHttp.limitedString());

            int status = resp.statusCode();
            if (status != 200 && status != 206) return null;

            String body  = resp.body() == null ? "" : resp.body();
            String lower = body.toLowerCase(Locale.ROOT);

            // Anti-FP: deve ter conteúdo relevante — não apenas uma página 200 genérica.
            // Debug endpoints usam probeDebugEndpoint() com markers próprios; aqui só Actuator.
            boolean confirmed = false;
            if ("ACTUATOR".equals(type)) {
                for (String marker : ACTUATOR_MARKERS) {
                    if (lower.contains(marker.toLowerCase(Locale.ROOT))) {
                        confirmed = true;
                        break;
                    }
                }
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

    /**
     * Sonda um endpoint de debug exigindo confirmação por marcador/formato
     * (SPAs respondem 200 + index.html em qualquer rota — sem marcador, descarta).
     */
    private SourceMapFinding probeDebugEndpoint(String url, DebugTarget target) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .GET()
                    .timeout(Duration.ofSeconds(8))
                    .header("User-Agent", ScannerHttp.USER_AGENT)
                    .header("Accept", "application/json,text/html,*/*")
                    .build();
            HttpResponse<String> resp = client.send(req, ScannerHttp.limitedString());

            int status = resp.statusCode();
            if (status != 200 && status != 206) return null;

            String body  = resp.body() == null ? "" : resp.body();
            String lower = body.toLowerCase(Locale.ROOT);
            String contentType = resp.headers()
                    .firstValue("content-type").orElse("").toLowerCase(Locale.ROOT);

            if (!confirmsDebugContent(target, body, lower, contentType)) return null;

            return SourceMapFinding.builder()
                    .type("DEBUG_ENDPOINT")
                    .url(url)
                    .evidence(target.description() + " (HTTP " + status + ")")
                    .severity("MEDIUM")
                    .build();

        } catch (Exception ignored) {}
        return null;
    }

    /**
     * Confirma se o corpo corresponde de fato à ferramenta de debug esperada.
     * - Arquivos (.env / config.json): validação por formato (não-HTML + shape).
     * - Demais: exige ao menos um marcador específico da ferramenta.
     * Sem confirmação → provável SPA fallback → descartar (preferimos FN a FP).
     */
    private boolean confirmsDebugContent(DebugTarget t, String body, String lower, String contentType) {
        boolean isHtml = lower.contains("<!doctype html") || lower.contains("<html");

        if (t.path().endsWith(".env")) {
            if (isHtml || body.isBlank()) return false;          // SPA fallback / vazio
            return body.contains("=") && (
                    lower.contains("app_")     || lower.contains("db_")  ||
                    lower.contains("secret")   || lower.contains("key")  ||
                    lower.contains("password") || lower.contains("token"));
        }
        if (t.path().endsWith("config.json")) {
            if (isHtml) return false;                            // SPA fallback
            String trimmed = body.trim();
            boolean json = contentType.contains("application/json")
                    || trimmed.startsWith("{") || trimmed.startsWith("[");
            return json && trimmed.length() > 2;                 // não apenas "{}" / "[]"
        }

        for (String marker : t.markers()) {
            if (lower.contains(marker)) return true;
        }
        return false;
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private String fetch(String url) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .GET()
                    .timeout(Duration.ofSeconds(10))
                    .header("User-Agent", ScannerHttp.USER_AGENT)
                    .build();
            HttpResponse<String> resp = client.send(req, ScannerHttp.limitedString());
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

    /** Endpoint de debug com marcadores de confirmação específicos da ferramenta. */
    private record DebugTarget(String path, String description, List<String> markers) {}
}
