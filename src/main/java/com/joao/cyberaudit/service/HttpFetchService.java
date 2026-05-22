package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.HttpFetchResult;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

@Service
public class HttpFetchService {

    // connectTimeout: tempo máximo para estabelecer a conexão TCP
    // Reduzido de 8s para 5s — se o servidor não responde em 5s, não vale esperar mais
    private final HttpClient clientFollow = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.ALWAYS)
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    private final HttpClient clientNoRedirect = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    public HttpFetchResult fetchHeaders(String url) {
        try {
            URI uri = URI.create(url);
            HttpResponse<Void> headResp = sendHead(uri);

            if (headResp.statusCode() == 405 || headResp.statusCode() == 501) {
                return buildResult(sendGet(uri));
            }
            return buildResult(headResp);

        } catch (Exception e) {
            return new HttpFetchResult(0, url, Map.of(), List.of(),
                    "Erro ao conectar: " + e.getMessage());
        }
    }

    public Map<String, String> fetchWithOrigin(String url, String origin) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .GET()
                    .timeout(Duration.ofSeconds(6)) // era 10s
                    .header("User-Agent", "CyberAuditScanner/1.0")
                    .header("Origin", origin)
                    .build();

            HttpResponse<Void> resp = clientFollow.send(req, HttpResponse.BodyHandlers.discarding());
            Map<String, String> normalized = new LinkedHashMap<>();
            resp.headers().map().forEach((k, v) -> {
                if (k != null && v != null && !v.isEmpty())
                    normalized.put(k.toLowerCase(Locale.ROOT), v.get(0));
            });
            return normalized;

        } catch (Exception e) {
            return Map.of();
        }
    }

    public boolean traceRedirectToHttps(String httpUrl) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(httpUrl))
                    .GET()
                    .timeout(Duration.ofSeconds(5)) // era 8s
                    .header("User-Agent", "CyberAuditScanner/1.0")
                    .header("Accept", "*/*")
                    .build();

            HttpResponse<Void> resp = clientFollow.send(req, HttpResponse.BodyHandlers.discarding());
            return resp.uri().toString().startsWith("https://");

        } catch (java.net.ConnectException | java.net.http.HttpConnectTimeoutException e) {
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private HttpResponse<Void> sendHead(URI uri) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(uri)
                .method("HEAD", HttpRequest.BodyPublishers.noBody())
                .timeout(Duration.ofSeconds(6)) // era 10s
                .header("User-Agent", "CyberAuditScanner/1.0")
                .build();
        return clientFollow.send(req, HttpResponse.BodyHandlers.discarding());
    }

    private HttpResponse<Void> sendGet(URI uri) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(uri)
                .GET()
                .timeout(Duration.ofSeconds(8)) // era 12s
                .header("User-Agent", "CyberAuditScanner/1.0")
                .header("Accept", "*/*")
                .build();
        return clientFollow.send(req, HttpResponse.BodyHandlers.discarding());
    }

    private HttpFetchResult buildResult(HttpResponse<Void> resp) {
        int status = resp.statusCode();
        String finalUrl = resp.uri().toString();

        Map<String, String> normalized = new LinkedHashMap<>();
        resp.headers().map().forEach((k, v) -> {
            if (k == null || v == null || v.isEmpty()) return;
            normalized.put(k.toLowerCase(Locale.ROOT), v.get(0));
        });

        List<String> rawSetCookies = resp.headers().allValues("set-cookie");
        if (rawSetCookies == null) rawSetCookies = Collections.emptyList();

        return new HttpFetchResult(status, finalUrl, normalized, rawSetCookies, null);
    }

    private URI resolveRedirect(URI base, String location) {
        if (location.startsWith("//"))
            return URI.create(base.getScheme() + ":" + location);
        return base.resolve(location);
    }
}