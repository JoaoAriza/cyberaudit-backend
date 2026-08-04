package com.joao.cyberaudit.service;

import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

@Service
public class SecurityTxtService {

    /**
     * security.txt é um padrão RFC 9116 que define como reportar
     * vulnerabilidades de segurança encontradas em um site.
     * Ausência não é vulnerabilidade crítica, mas indica maturidade
     * de segurança baixa — especialmente relevante para desenvolvedores.
     *
     * Locais padrão: /.well-known/security.txt ou /security.txt
     */

    private final HttpClient client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)  // redirects seguidos por ScannerHttp.sendFollowingSafely (revalida cada hop)
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    public SecurityTxtResult check(String baseUrl) {
        String base = extractBase(baseUrl);
        if (base == null) return new SecurityTxtResult(false, null, "URL inválida");

        String primary   = base + "/.well-known/security.txt";
        String secondary = base + "/security.txt";

        SecurityTxtResult result = probe(primary);
        if (result.found()) return result;

        return probe(secondary);
    }

    private SecurityTxtResult probe(String url) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .GET()
                    .timeout(Duration.ofSeconds(5))
                    .header("User-Agent", ScannerHttp.USER_AGENT)
                    .build();

            HttpResponse<String> resp = ScannerHttp.sendFollowingSafely(client, 
                    req, ScannerHttp.limitedString());

            if (resp.statusCode() != 200) return new SecurityTxtResult(false, null, null);

            String body = resp.body() == null ? "" : resp.body().trim();

            if (!body.toLowerCase().contains("contact:")) {
                return new SecurityTxtResult(false, null,
                        "Arquivo encontrado mas sem campo Contact obrigatório");
            }

            String contact = extractField(body, "Contact");
            return new SecurityTxtResult(true, contact, null);

        } catch (Exception e) {
            return new SecurityTxtResult(false, null, null);
        }
    }

    private String extractField(String body, String field) {
        for (String line : body.split("\\r?\\n")) {
            if (line.toLowerCase().startsWith(field.toLowerCase() + ":")) {
                return line.substring(field.length() + 1).trim();
            }
        }
        return null;
    }

    private String extractBase(String url) {
        try {
            URI uri = URI.create(url);
            int port = uri.getPort();
            if (port > 0 && port != 80 && port != 443)
                return uri.getScheme() + "://" + uri.getHost() + ":" + port;
            return uri.getScheme() + "://" + uri.getHost();
        } catch (Exception e) {
            return null;
        }
    }

    public record SecurityTxtResult(boolean found, String contact, String message) {}
}