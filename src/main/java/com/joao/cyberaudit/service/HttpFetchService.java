package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.HttpFetchResult;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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

    // CSP via <meta http-equiv="Content-Security-Policy" content="...">. Duas ordens de
    // atributo. O delimitador do content é group(1), fechado por backreference \1, então o
    // valor (group(2)) pode conter o outro tipo de aspas — caso da CSP ('self', 'none').
    private static final Pattern META_CSP = Pattern.compile(
            "<meta[^>]+http-equiv\\s*=\\s*[\"']content-security-policy[\"'][^>]*content\\s*=\\s*([\"'])(.*?)\\1",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern META_CSP_CONTENT_FIRST = Pattern.compile(
            "<meta[^>]+content\\s*=\\s*([\"'])(.*?)\\1[^>]*http-equiv\\s*=\\s*[\"']content-security-policy[\"']",
            Pattern.CASE_INSENSITIVE);

    public HttpFetchResult fetchHeaders(String url) {
        try {
            URI uri = URI.create(url);
            // GET (não HEAD): captura headers de segurança e Set-Cookie que alguns
            // servidores só enviam no GET, e lê o corpo para extrair a CSP via <meta>.
            return buildResult(sendGet(uri));

        } catch (Exception e) {
            return new HttpFetchResult(0, url, Map.of(), List.of(),
                    "Erro ao conectar: " + e.getMessage());
        }
    }

    public Map<String, String> fetchWithOrigin(String url, String origin) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .GET()
                    .timeout(Duration.ofSeconds(6))
                    .header("User-Agent", ScannerHttp.USER_AGENT)
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
                    .timeout(Duration.ofSeconds(5))
                    .header("User-Agent", ScannerHttp.USER_AGENT)
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

    private HttpResponse<String> sendGet(URI uri) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(uri)
                .GET()
                .timeout(Duration.ofSeconds(8))
                .header("User-Agent", ScannerHttp.USER_AGENT)
                .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
                .build();
        return clientFollow.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private HttpFetchResult buildResult(HttpResponse<String> resp) {
        int status = resp.statusCode();
        String finalUrl = resp.uri().toString();

        Map<String, String> normalized = new LinkedHashMap<>();
        resp.headers().map().forEach((k, v) -> {
            if (k == null || v == null || v.isEmpty()) return;
            normalized.put(k.toLowerCase(Locale.ROOT), v.get(0));
        });

        // CSP via <meta http-equiv>: se não veio como header, extrai do HTML (equivalente
        // funcional do header para a maioria das diretivas; SPAs entregam a CSP assim).
        if (!normalized.containsKey("content-security-policy")) {
            String metaCsp = extractMetaCsp(resp.body());
            if (metaCsp != null && !metaCsp.isBlank()) {
                normalized.put("content-security-policy", metaCsp.trim());
            }
        }

        List<String> rawSetCookies = resp.headers().allValues("set-cookie");
        if (rawSetCookies == null) rawSetCookies = Collections.emptyList();

        return new HttpFetchResult(status, finalUrl, normalized, rawSetCookies, null);
    }

    /** Extrai a CSP de uma tag &lt;meta http-equiv="Content-Security-Policy"&gt; no HTML. */
    private String extractMetaCsp(String body) {
        if (body == null || body.isBlank()) return null;
        Matcher m = META_CSP.matcher(body);
        if (m.find()) return m.group(2);
        m = META_CSP_CONTENT_FIRST.matcher(body);
        if (m.find()) return m.group(2);
        return null;
    }

    private URI resolveRedirect(URI base, String location) {
        if (location.startsWith("//"))
            return URI.create(base.getScheme() + ":" + location);
        return base.resolve(location);
    }
}