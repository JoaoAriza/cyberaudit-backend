package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.SensitiveFileFinding;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

@Service
public class SensitiveFileService {

    private static final List<FileTarget> TARGETS = List.of(
            new FileTarget("/.env",                    "CRITICAL"),
            new FileTarget("/.env.local",              "CRITICAL"),
            new FileTarget("/.env.production",         "CRITICAL"),
            new FileTarget("/.env.backup",             "CRITICAL"),
            new FileTarget("/wp-config.php",           "CRITICAL"),
            new FileTarget("/wp-config.php.bak",       "CRITICAL"),
            new FileTarget("/wp-config-sample.php",    "MEDIUM"),
            new FileTarget("/config.php",              "HIGH"),
            new FileTarget("/configuration.php",       "HIGH"),
            new FileTarget("/config/database.php",     "CRITICAL"),
            new FileTarget("/app/config/database.yml", "CRITICAL"),
            new FileTarget("/backup.sql",              "CRITICAL"),
            new FileTarget("/backup.zip",              "HIGH"),
            new FileTarget("/db.sql",                  "CRITICAL"),
            new FileTarget("/dump.sql",                "CRITICAL"),
            new FileTarget("/database.sql",            "CRITICAL"),
            new FileTarget("/.git/config",             "HIGH"),
            new FileTarget("/.git/HEAD",               "HIGH"),
            new FileTarget("/storage/logs/laravel.log","HIGH"),
            new FileTarget("/actuator/env",            "CRITICAL"),
            new FileTarget("/actuator/beans",          "HIGH"),
            new FileTarget("/actuator/mappings",       "MEDIUM"),
            new FileTarget("/application.properties",  "HIGH"),
            new FileTarget("/application.yml",         "HIGH"),
            new FileTarget("/server-status",           "MEDIUM"),
            new FileTarget("/phpinfo.php",             "HIGH"),
            new FileTarget("/.htpasswd",               "CRITICAL"),
            new FileTarget("/.htaccess",               "MEDIUM"),
            new FileTarget("/crossdomain.xml",         "MEDIUM"),
            new FileTarget("/clientaccesspolicy.xml",  "MEDIUM")
    );

    private final HttpClient client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    public List<SensitiveFileFinding> scan(String baseUrl) {
        List<SensitiveFileFinding> findings = new ArrayList<>();
        String base = extractBase(baseUrl);
        if (base == null) return findings;

        for (FileTarget target : TARGETS) {
            SensitiveFileFinding finding = probe(base, target);
            if (finding != null) findings.add(finding);
        }

        return findings;
    }

    private SensitiveFileFinding probe(String base, FileTarget target) {
        try {
            String url = base + target.path;

            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .GET()
                    .timeout(Duration.ofSeconds(5))
                    .header("User-Agent", "CyberAuditScanner/1.0")
                    .build();

            HttpResponse<String> resp = client.send(
                    req, HttpResponse.BodyHandlers.ofString());

            int status = resp.statusCode();

            if (status == 404 || status == 410 || status >= 500) return null;
            if (status == 301 || status == 302)                   return null;

            String exposure;
            String preview = null;

            if (status == 200) {
                String body = resp.body() == null ? "" : resp.body().trim();
                String contentType = resp.headers()
                        .firstValue("content-type").orElse("").toLowerCase();

                if (!isRealContent(target.path, body, contentType)) return null;

                exposure = "EXPOSED";
                preview  = body.length() > 150 ? body.substring(0, 150) + "..." : body;

            } else if (status == 403) {
                exposure = "PROTECTED";
            } else {
                return null;
            }

            return new SensitiveFileFinding(
                    target.path, status, exposure, preview, target.severity);

        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Verifica se o body é realmente o arquivo sensível esperado.
     *
     * Problema principal: SPAs (React, Vue, Next) retornam HTTP 200 com
     * <!DOCTYPE html> para qualquer path — incluindo /actuator/env, /phpinfo.php, etc.
     * Precisamos distinguir o conteúdo real do HTML genérico de fallback.
     */
    private boolean isRealContent(String path, String body, String contentType) {
        if (body.isBlank()) return false;

        String lower     = body.toLowerCase(Locale.ROOT);
        String lowerPath = path.toLowerCase(Locale.ROOT);

        boolean isHtml = lower.contains("<!doctype html") || lower.contains("<html");

        // ── Actuator (Spring Boot) ─────────────────────────────────────────────
        // JSON real contém campos específicos como "activeProfiles", "beans", etc.
        // HTML genérico de SPA não contém esses campos.
        if (lowerPath.contains("actuator")) {
            if (isHtml) return false; // SPA fallback — falso positivo
            // Conteúdo real do actuator é JSON
            return contentType.contains("application/json") ||
                    lower.contains("\"activeprofiles\"") ||
                    lower.contains("\"beans\"") ||
                    lower.contains("\"mappings\"") ||
                    lower.contains("\"propertysources\"") ||
                    lower.contains("\"contexts\"");
        }

        // ── phpinfo.php ────────────────────────────────────────────────────────
        // phpinfo real tem estrutura muito específica com tabelas PHP
        if (lowerPath.contains("phpinfo")) {
            if (!isHtml) return false;
            // phpinfo real contém estas strings específicas
            return lower.contains("php version") ||
                    lower.contains("phpinfo()") ||
                    lower.contains("php credits") ||
                    lower.contains("configuration file") ||
                    lower.contains("zend engine");
        }

        // ── Qualquer outro arquivo HTML → SPA fallback, descartar ─────────────
        if (isHtml) return false;

        // ── .env ──────────────────────────────────────────────────────────────
        if (lowerPath.endsWith(".env") ||
                lowerPath.endsWith(".env.local") ||
                lowerPath.endsWith(".env.production") ||
                lowerPath.endsWith(".env.backup")) {
            // .env real tem pares KEY=VALUE, geralmente com APP_, DB_, etc.
            return body.contains("=") &&
                    (lower.contains("app_") || lower.contains("db_") ||
                            lower.contains("secret") || lower.contains("key") ||
                            lower.contains("password") || lower.contains("token") ||
                            // Qualquer linha no formato KEY=VALUE
                            body.matches("(?s).*[A-Z_]+=.+.*"));
        }

        // ── SQL dumps ─────────────────────────────────────────────────────────
        if (lowerPath.endsWith(".sql")) {
            return lower.contains("insert into") || lower.contains("create table") ||
                    lower.contains("drop table")  || lower.contains("alter table");
        }

        // ── Git ───────────────────────────────────────────────────────────────
        if (lowerPath.contains(".git")) {
            return lower.contains("[core]") || lower.contains("ref:") ||
                    lower.contains("repositoryformatversion");
        }

        // ── PHP config files ──────────────────────────────────────────────────
        if (lowerPath.endsWith(".php")) {
            return lower.contains("<?php") ||
                    lower.contains("define(") ||
                    lower.contains("$db_");
        }

        // ── YAML / Properties ─────────────────────────────────────────────────
        if (lowerPath.endsWith(".yml") || lowerPath.endsWith(".yaml") ||
                lowerPath.endsWith(".properties")) {
            return body.contains(":") &&
                    (lower.contains("datasource") || lower.contains("database") ||
                            lower.contains("password") || lower.contains("secret") ||
                            lower.contains("spring") || lower.contains("server.port"));
        }

        // ── crossdomain.xml / clientaccesspolicy.xml ─────────────────────────
        if (lowerPath.endsWith(".xml")) {
            return lower.contains("cross-domain-policy") ||
                    lower.contains("cross-domain-access") ||
                    lower.contains("clientaccesspolicy");
        }

        // ── .htpasswd ─────────────────────────────────────────────────────────
        if (lowerPath.contains(".htpasswd")) {
            // htpasswd contém user:hash (bcrypt, MD5, etc.)
            return body.matches("(?s).*\\w+:\\$.*");
        }

        // ── .htaccess ─────────────────────────────────────────────────────────
        if (lowerPath.contains(".htaccess")) {
            return lower.contains("rewriterule") || lower.contains("allow from") ||
                    lower.contains("deny from")   || lower.contains("authtype");
        }

        // ── server-status (Apache) ────────────────────────────────────────────
        if (lowerPath.contains("server-status")) {
            return lower.contains("apache") && lower.contains("server status");
        }

        // ── .bak (backups de PHP/config, ex: wp-config.php.bak) ──────────────
        // Não termina com .php portanto não é capturado pelo check anterior.
        // Backup real contém PHP ou pares KEY=VALUE de credenciais.
        if (lowerPath.endsWith(".bak")) {
            return lower.contains("<?php")  || lower.contains("define(") ||
                   lower.contains("db_")    || lower.contains("database") ||
                   (body.contains("=") && body.matches("(?s).*[A-Z_]+=.+.*"));
        }

        // ── .zip / compactados ─────────────────────────────────────────────────
        // Zip real começa com magic bytes "PK" (0x50 0x4B).
        // Evita falso positivo quando servidor devolve 200+text/plain para path inexistente.
        if (lowerPath.endsWith(".zip")    || lowerPath.endsWith(".tar.gz") ||
                lowerPath.endsWith(".tgz")) {
            return body.startsWith("PK") ||
                   contentType.contains("application/zip") ||
                   contentType.contains("application/octet-stream") ||
                   contentType.contains("application/x-tar");
        }

        // ── .log (Laravel e outros frameworks) ─────────────────────────────────
        // Laravel: "[YYYY-MM-DD HH:MM:SS] env.LEVEL: mensagem"
        // Evita falso positivo com respostas de erro genéricas em texto plano.
        if (lowerPath.endsWith(".log")) {
            return lower.contains("local.error")      || lower.contains("production.error") ||
                   lower.contains("local.debug")      || lower.contains("local.info") ||
                   lower.contains("stack trace")       || lower.contains("exception in") ||
                   lower.contains("] local.")          || lower.contains("] production.");
        }

        // Nenhum check específico correspondeu — não reportar.
        // Preferimos falso negativo a falso positivo para arquivos sem padrão conhecido.
        return false;
    }

    private String extractBase(String url) {
        try {
            URI uri    = URI.create(url);
            String scheme = uri.getScheme();
            String host   = uri.getHost();
            int    port   = uri.getPort();
            if (port > 0 && port != 80 && port != 443)
                return scheme + "://" + host + ":" + port;
            return scheme + "://" + host;
        } catch (Exception e) {
            return null;
        }
    }

    private record FileTarget(String path, String severity) {}
}