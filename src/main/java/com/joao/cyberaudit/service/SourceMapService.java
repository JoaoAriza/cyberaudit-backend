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
     * Endpoint Actuator sondado, com o que confirma que ele é mesmo um Actuator.
     *
     * @param chave    id no catálogo de mensagens ({@code evidence.<chave>})
     * @param markers  chaves JSON que a resposta DAQUELE endpoint tem de conter,
     *                 em minúsculas. Específicas por endpoint de propósito — ver
     *                 o javadoc de {@link #probeActuator}.
     */
    record ActuatorTarget(String path, String severity, String chave, List<String> markers) {}

    /**
     * Endpoints do Spring Boot Actuator, com o formato real de cada resposta.
     *
     * <h2>Por que os marcadores são por endpoint</h2>
     *
     * Havia UMA lista global de marcadores genéricos, casada por substring contra o
     * corpo inteiro. Um deles era {@code "status"} — e o perfil
     * {@code github.com/actuator} foi reportado como "Actuator exposto" porque o HTML
     * do GitHub tem <b>{@code role="status"}</b>, um atributo de acessibilidade.
     *
     * Confirmar {@code /actuator/env} com um marcador que só existe em
     * {@code /actuator/health} nunca fez sentido; o que salvava era a coincidência de
     * os dois serem JSON. Agora cada endpoint é confirmado pelo que ELE devolve.
     */
    static final List<ActuatorTarget> ACTUATOR_ENDPOINTS = List.of(
            // Alta severidade — expõem config, segredos, heap.
            new ActuatorTarget("/actuator/env",        "HIGH", "ACTUATOR_ENV",
                    List.of("\"propertysources\"", "\"activeprofiles\"")),
            new ActuatorTarget("/actuator/beans",      "HIGH", "ACTUATOR_BEANS",
                    List.of("\"beans\"")),
            // Binário (HPROF), não JSON — tratado à parte em probeActuator.
            new ActuatorTarget("/actuator/heapdump",   "HIGH", "ACTUATOR_HEAPDUMP",
                    List.of()),
            new ActuatorTarget("/actuator/threaddump", "HIGH", "ACTUATOR_THREADDUMP",
                    List.of("\"threads\"", "\"threadname\"")),
            new ActuatorTarget("/actuator/loggers",    "HIGH", "ACTUATOR_LOGGERS",
                    List.of("\"loggers\"", "\"levels\"")),
            new ActuatorTarget("/actuator/mappings",   "HIGH", "ACTUATOR_MAPPINGS",
                    List.of("\"mappings\"", "\"dispatcherservlets\"")),

            // Média severidade.
            new ActuatorTarget("/actuator",            "MEDIUM", "ACTUATOR_ROOT",
                    List.of("\"_links\"")),
            // `/actuator/info` responde `{}` quando nada foi configurado. Sem build/git
            // não há informação exposta — e achado sem nada exposto é ruído.
            new ActuatorTarget("/actuator/info",       "MEDIUM", "ACTUATOR_INFO",
                    List.of("\"build\"", "\"git\"", "\"app\"")),
            new ActuatorTarget("/actuator/metrics",    "MEDIUM", "ACTUATOR_METRICS",
                    List.of("\"names\"")),
            new ActuatorTarget("/actuator/conditions", "MEDIUM", "ACTUATOR_CONDITIONS",
                    List.of("\"positivematches\"", "\"negativematches\""))
    );

    /** Assinatura de um heap dump HPROF — os primeiros bytes do arquivo. */
    private static final String HPROF_MAGIC = "JAVA PROFILE";

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
            new DebugTarget("/_profiler",            "DEBUG_SYMFONY_PROFILER",
                    List.of("sf-toolbar", "symfony profiler", "sf-profiler", "/_profiler/")),
            new DebugTarget("/_profiler/phpinfo",    "DEBUG_SYMFONY_PHPINFO",
                    List.of("php version", "phpinfo()", "zend engine")),
            new DebugTarget("/debug/default/view",   "DEBUG_YII2",
                    List.of("yii debugger", "/debug/default/")),
            new DebugTarget("/__debugbar/open",      "DEBUG_LARAVEL_DEBUGBAR",
                    List.of("debugbar", "\"__meta\"", "\"php\":")),
            new DebugTarget("/console",              "DEBUG_CONSOLE",
                    List.of("werkzeug", "h2 console", "interactive console", "wsgi")),
            new DebugTarget("/telescope",            "DEBUG_TELESCOPE",
                    List.of("/vendor/telescope", "window.telescope", "laravel telescope")),
            new DebugTarget("/horizon",              "DEBUG_HORIZON",
                    List.of("/vendor/horizon", "window.horizon", "laravel horizon")),
            new DebugTarget("/phpinfo.php",          "DEBUG_PHPINFO",
                    List.of("php version", "phpinfo()", "zend engine")),
            new DebugTarget("/info.php",             "DEBUG_PHPINFO",
                    List.of("php version", "phpinfo()", "zend engine")),
            new DebugTarget("/server-info",          "DEBUG_SERVER_INFO",
                    List.of("apache server information", "server settings")),
            new DebugTarget("/.env",                 "DEBUG_ENV_FILE",
                    List.of()),
            new DebugTarget("/config.json",          "DEBUG_CONFIG_JSON",
                    List.of()),
            new DebugTarget("/app/config.json",      "DEBUG_APP_CONFIG",
                    List.of()),
            new DebugTarget("/rails/info/properties","DEBUG_RAILS_INFO",
                    List.of("ruby version", "rails version", "rack version")),
            new DebugTarget("/rails/info/routes",    "DEBUG_RAILS_ROUTES",
                    List.of("controller#action", "uri pattern"))
    );

    /**
     * Regex para extrair src de tags <script> no HTML.
     */
    private static final Pattern SCRIPT_SRC = Pattern.compile(
            "<script[^>]+src=[\"']([^\"']+\\.js(?:\\?[^\"']*)?)[\"']",
            Pattern.CASE_INSENSITIVE
    );

    private final MessageCatalog catalog;

    public SourceMapService(MessageCatalog catalog) {
        this.catalog = catalog;
    }

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

        // 2. Spring Boot Actuator
        for (ActuatorTarget entry : ACTUATOR_ENDPOINTS) {
            SourceMapFinding f = probeActuator(base + entry.path(), entry);
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

    /**
     * Sonda um endpoint do Actuator, em três barreiras.
     *
     * <ol>
     *   <li><b>Não pode ser HTML.</b> Actuator serve JSON
     *       ({@code application/vnd.spring-boot.actuator.v3+json}); nenhuma resposta
     *       {@code text/html} é um Actuator. Só esta barreira já derruba o caso que
     *       originou a correção — {@code github.com/actuator} é o perfil de um usuário
     *       chamado "actuator", HTTP 200 e HTML;</li>
     *   <li><b>Tem de parecer JSON</b> — content-type de JSON, ou corpo começando em
     *       <code>{</code>/<code>[</code>;</li>
     *   <li><b>Marcador do PRÓPRIO endpoint.</b> Antes bastava um marcador genérico
     *       qualquer, casado por substring: {@code "status"} casava com o
     *       {@code role="status"} de qualquer página acessível.</li>
     * </ol>
     *
     * O heapdump é a exceção: é binário (HPROF), não JSON, e se identifica pela
     * assinatura no início do arquivo.
     *
     * Na dúvida, descarta. Falso negativo custa um achado; falso positivo custa a
     * credibilidade do laudo inteiro — e é o cliente que descobre, como aqui.
     */
    private SourceMapFinding probeActuator(String url, ActuatorTarget target) {
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

            if (!confirmaActuator(target, body, lower, contentType)) return null;

            return SourceMapFinding.builder()
                    .type("ACTUATOR")
                    .url(url)
                    .evidence(catalog.evidence(target.chave()) + " (HTTP " + status + ")")
                    .severity(target.severity())
                    .build();

        } catch (Exception ignored) {}
        return null;
    }

    /** As três barreiras descritas em {@link #probeActuator}. */
    boolean confirmaActuator(ActuatorTarget t, String body, String lower, String contentType) {
        // Heapdump: binário, identificado pela assinatura HPROF. Antes ele nunca era
        // reportado — nenhum marcador JSON casa com um dump binário —, então o achado
        // mais grave da família era o único que não funcionava.
        if (t.markers().isEmpty()) {
            return body.startsWith(HPROF_MAGIC)
                    || contentType.contains("application/octet-stream") && body.length() > 512;
        }

        if (contentType.contains("text/html")
                || lower.contains("<!doctype html") || lower.contains("<html")) return false;

        String trimmed = body.trim();
        boolean pareceJson = contentType.contains("json")
                || trimmed.startsWith("{") || trimmed.startsWith("[");
        if (!pareceJson) return false;

        return t.markers().stream().anyMatch(lower::contains);
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
                    .evidence(catalog.evidence(target.chave()) + " (HTTP " + status + ")")
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
    /** @param chave id no catálogo — {@code evidence.<chave>} */
    private record DebugTarget(String path, String chave, List<String> markers) {}
}
