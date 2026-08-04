package com.joao.cyberaudit.service;

import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

@Service
public class RobotsTxtService {

    private static final Set<String> SENSITIVE_PREFIXES = Set.of(
            "/admin", "/administrator",
            "/api/", "/api",
            "/backup", "/backups",
            "/config", "/configuration",
            "/db", "/database",
            "/private", "/secret",
            "/staging", "/dev", "/test",
            "/.git", "/.env",
            "/phpmyadmin",
            "/wp-admin", "/wp-login",
            "/uploads", "/files",
            "/logs", "/debug",
            "/console", "/actuator", "/env"
    );

    private final HttpClient client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)  // redirects seguidos por ScannerHttp.sendFollowingSafely (revalida cada hop)
            .connectTimeout(Duration.ofSeconds(6))
            .build();

    public List<String> findSensitivePaths(String baseUrl) {
        List<String> found = new ArrayList<>();
        try {
            String body = fetchRobots(buildRobotsUrl(baseUrl));
            if (body == null) return found;

            for (String line : body.split("\\r?\\n")) {
                line = line.trim();
                if (!line.toLowerCase(Locale.ROOT).startsWith("disallow:")) continue;

                String path = line.substring("disallow:".length()).trim();
                int commentIdx = path.indexOf('#');
                if (commentIdx >= 0) path = path.substring(0, commentIdx).trim();

                if (isSensitive(path)) found.add(path);
            }
        } catch (Exception ignored) {}
        return found;
    }

    private boolean isSensitive(String path) {
        if (path == null || path.isBlank() || path.equals("/")) return false;
        String lower = path.toLowerCase(Locale.ROOT);
        return SENSITIVE_PREFIXES.stream().anyMatch(lower::startsWith);
    }

    private String buildRobotsUrl(String baseUrl) {
        try {
            URI uri = URI.create(baseUrl);
            return uri.getScheme() + "://" + uri.getHost()
                    + (uri.getPort() > 0 ? ":" + uri.getPort() : "")
                    + "/robots.txt";
        } catch (Exception e) {
            return baseUrl + "/robots.txt";
        }
    }

    private String fetchRobots(String url) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .GET()
                    .timeout(Duration.ofSeconds(8))
                    .header("User-Agent", ScannerHttp.USER_AGENT)
                    .build();
            HttpResponse<String> resp = ScannerHttp.sendFollowingSafely(client, req, ScannerHttp.limitedString());
            if (resp.statusCode() != 200) return null;
            return resp.body();
        } catch (Exception e) {
            return null;
        }
    }
}