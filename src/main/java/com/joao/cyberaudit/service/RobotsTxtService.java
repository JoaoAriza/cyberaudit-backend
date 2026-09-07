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

    /** Diretivas que identificam um robots.txt de verdade quando o Content-Type não ajuda. */
    private static final Set<String> ROBOTS_DIRECTIVES = Set.of(
            "user-agent:", "disallow:", "allow:", "sitemap:", "crawl-delay:");

    private final HttpClient client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)  // redirects seguidos por ScannerHttp.sendFollowingSafely (revalida cada hop)
            .connectTimeout(Duration.ofSeconds(6))
            .build();

    /**
     * Resultado do módulo: presença do arquivo e paths sensíveis declarados.
     *
     * Sem o `present`, "o site não tem robots.txt" e "o robots.txt não expõe
     * nada" produziam exatamente a mesma resposta — uma lista vazia — e a UI
     * dava OK nos dois casos, afirmando ter analisado um arquivo inexistente.
     */
    public record RobotsTxtResult(boolean present, List<String> sensitivePaths) {
        public static RobotsTxtResult ausente() {
            return new RobotsTxtResult(false, List.of());
        }
    }

    public RobotsTxtResult check(String baseUrl) {
        String body = fetchRobots(buildRobotsUrl(baseUrl));
        if (body == null) return RobotsTxtResult.ausente();
        return new RobotsTxtResult(true, extractSensitivePaths(body));
    }

    private List<String> extractSensitivePaths(String body) {
        List<String> found = new ArrayList<>();
        try {
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

            String body = resp.body();
            String contentType = resp.headers().firstValue("content-type").orElse("");

            return looksLikeRobotsTxt(body, contentType) ? body : null;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Hospedagem de SPA (Cloudflare Pages, Netlify, Vercel) responde o
     * index.html com HTTP 200 para qualquer caminho pedido. Aceitar isso como
     * robots.txt fazia o parser não achar nenhum `Disallow:` no HTML e concluir
     * "sem exposições" — laudo verde para um arquivo que não existe.
     *
     * Content-Type resolve o caso limpo, mas há servidor legítimo que serve
     * robots.txt como octet-stream, então quando o cabeçalho não confirma
     * exigimos ao menos uma diretiva reconhecida no corpo.
     */
    private boolean looksLikeRobotsTxt(String body, String contentType) {
        if (body == null) return false;

        String trimmed = body.trim();
        if (trimmed.startsWith("<")) return false;   // HTML/XML nunca é robots.txt

        if (contentType.toLowerCase(Locale.ROOT).startsWith("text/plain")) return true;

        String lower = trimmed.toLowerCase(Locale.ROOT);
        return ROBOTS_DIRECTIVES.stream().anyMatch(lower::contains);
    }
}