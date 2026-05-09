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

    /**
     * Arquivos que nunca deveriam ser acessíveis publicamente.
     * Cada entrada: {path, severidade}
     *
     * Critério de severidade:
     * CRITICAL — exposição direta de credenciais ou configuração de banco
     * HIGH     — configuração da aplicação ou arquivos de ambiente
     * MEDIUM   — metadados que facilitam reconhecimento
     */
    private static final List<FileTarget> TARGETS = List.of(
            // Ambiente e credenciais
            new FileTarget("/.env",                    "CRITICAL"),
            new FileTarget("/.env.local",              "CRITICAL"),
            new FileTarget("/.env.production",         "CRITICAL"),
            new FileTarget("/.env.backup",             "CRITICAL"),

            // WordPress
            new FileTarget("/wp-config.php",           "CRITICAL"),
            new FileTarget("/wp-config.php.bak",       "CRITICAL"),
            new FileTarget("/wp-config-sample.php",    "MEDIUM"),

            // PHP genérico
            new FileTarget("/config.php",              "HIGH"),
            new FileTarget("/configuration.php",       "HIGH"),
            new FileTarget("/config/database.php",     "CRITICAL"),
            new FileTarget("/app/config/database.yml", "CRITICAL"),

            // Backups
            new FileTarget("/backup.sql",              "CRITICAL"),
            new FileTarget("/backup.zip",              "HIGH"),
            new FileTarget("/db.sql",                  "CRITICAL"),
            new FileTarget("/dump.sql",                "CRITICAL"),
            new FileTarget("/database.sql",            "CRITICAL"),

            // Git exposto
            new FileTarget("/.git/config",             "HIGH"),
            new FileTarget("/.git/HEAD",               "HIGH"),

            // Laravel
            new FileTarget("/.env",                    "CRITICAL"),
            new FileTarget("/storage/logs/laravel.log","HIGH"),

            // Spring Boot / Java
            new FileTarget("/actuator/env",            "CRITICAL"),
            new FileTarget("/actuator/beans",          "HIGH"),
            new FileTarget("/actuator/mappings",       "MEDIUM"),
            new FileTarget("/application.properties",  "HIGH"),
            new FileTarget("/application.yml",         "HIGH"),

            // Outros
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

            if (status == 301 || status == 302) return null;

            String exposure;
            String preview = null;

            if (status == 200) {
                exposure = "EXPOSED";
                String body = resp.body() == null ? "" : resp.body().trim();
                if (isRealContent(target.path, body)) {
                    preview = body.length() > 150
                            ? body.substring(0, 150) + "..."
                            : body;
                } else {
                    return null;
                }
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

    private boolean isRealContent(String path, String body) {
        if (body.isBlank()) return false;

        String lower = body.toLowerCase(Locale.ROOT);
        String lowerPath = path.toLowerCase(Locale.ROOT);

        if (lower.contains("<!doctype html") || lower.contains("<html")) {
            if (lowerPath.contains("phpinfo")) return true;
            if (lowerPath.contains("actuator")) return true;
            return false;
        }

        if (lowerPath.endsWith(".env") && body.contains("=")) return true;

        if (lowerPath.endsWith(".sql") &&
                (lower.contains("insert into") || lower.contains("create table")))
            return true;

        if (lowerPath.contains(".git") &&
                (lower.contains("[core]") || lower.contains("ref:")))
            return true;

        if (lowerPath.endsWith(".php") && lower.contains("<?php")) return true;

        if ((lowerPath.endsWith(".yml") || lowerPath.endsWith(".yaml") ||
                lowerPath.endsWith(".properties")) && body.contains(":"))
            return true;

        return body.length() > 50;
    }

    private String extractBase(String url) {
        try {
            URI uri = URI.create(url);
            String scheme = uri.getScheme();
            String host   = uri.getHost();
            int    port   = uri.getPort();

            if (port > 0 && port != 80 && port != 443) {
                return scheme + "://" + host + ":" + port;
            }
            return scheme + "://" + host;
        } catch (Exception e) {
            return null;
        }
    }

    private record FileTarget(String path, String severity) {}
}