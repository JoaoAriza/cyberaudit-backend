package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.HttpFetchResult;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

@Service
public class HttpFetchService {

    private final HttpClient clientFollow = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.ALWAYS)
            .connectTimeout(Duration.ofSeconds(8))
            .build();

    private final HttpClient clientNoRedirect = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(8))
            .build();

    // Usa redirects automáticos (bom para pegar finalUrl + headers finais)
    public HttpFetchResult fetchHeaders(String url) {
        try {
            URI uri = URI.create(url);

            HttpResponse<Void> headResp = sendHeadFollow(uri);

            // fallback se HEAD não for suportado
            if (headResp.statusCode() == 405 || headResp.statusCode() == 501) {
                HttpResponse<Void> getResp = sendGetFollow(uri);
                return buildResult(getResp);
            }

            return buildResult(headResp);

        } catch (Exception e) {
            return new HttpFetchResult(0, url, Map.of(), "Erro ao conectar: " + e.getMessage());
        }
    }

    // NOVO: segue manualmente redirects (sem auto-follow) e detecta se em algum passo vira HTTPS
    public boolean traceRedirectToHttps(String httpUrl) {
        try {
            URI current = URI.create(httpUrl);
            boolean sawHttps = current.toString().startsWith("https://");

            for (int i = 0; i < 10; i++) {
                HttpRequest req = HttpRequest.newBuilder(current)
                        .GET() // GET para evitar comportamento diferente em HEAD
                        .timeout(Duration.ofSeconds(12))
                        .header("User-Agent", "CyberAuditScanner/1.0")
                        .header("Accept", "/")
                        .build();

                HttpResponse<Void> resp = clientNoRedirect.send(req, HttpResponse.BodyHandlers.discarding());
                int status = resp.statusCode();

                // se não é redirect, acabou
                if (status < 300 || status >= 400) {
                    break;
                }

                String location = resp.headers().firstValue("location").orElse(null);
                if (location == null || location.isBlank()) {
                    break;
                }

                URI next = resolveRedirect(current, location);
                if (next.toString().startsWith("https://")) {
                    sawHttps = true;
                }

                current = next;
            }

            return sawHttps;

        } catch (Exception e) {
            return false;
        }
    }

    private URI resolveRedirect(URI base, String location) {
        // location pode ser:
        // - absoluta: https://...
        // - relativa: /path
        // - scheme-relative: //example.com/path
        if (location.startsWith("//")) {
            return URI.create(base.getScheme() + ":" + location);
        }
        return base.resolve(location);
    }

    private HttpResponse<Void> sendHeadFollow(URI uri) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(uri)
                .method("HEAD", HttpRequest.BodyPublishers.noBody())
                .timeout(Duration.ofSeconds(10))
                .header("User-Agent", "CyberAuditScanner/1.0")
                .build();

        return clientFollow.send(req, HttpResponse.BodyHandlers.discarding());
    }

    private HttpResponse<Void> sendGetFollow(URI uri) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(uri)
                .GET()
                .timeout(Duration.ofSeconds(12))
                .header("User-Agent", "CyberAuditScanner/1.0")
                .header("Accept", "/")
                .build();

        return clientFollow.send(req, HttpResponse.BodyHandlers.discarding());
    }

    private HttpFetchResult buildResult(HttpResponse<Void> resp) {
        int status = resp.statusCode();
        String finalUrl = resp.uri().toString();

        Map<String, String> normalized = new LinkedHashMap<>();
        resp.headers().map().forEach((k, v) -> {
            if (k == null) return;
            if (v == null || v.isEmpty()) return;
            normalized.put(k.toLowerCase(Locale.ROOT), v.get(0));
        });

        return new HttpFetchResult(status, finalUrl, normalized, null);
    }
}