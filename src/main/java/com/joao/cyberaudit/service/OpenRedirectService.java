package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.OpenRedirectFinding;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

@Service
public class OpenRedirectService {

    private static final String PROBE_DOMAIN = "https://open-redirect-probe.cyberaudit.io";

    private static final List<String> REDIRECT_PARAMS = List.of(
            "redirect", "redirect_to", "redirect_url",
            "url", "next", "return", "return_url",
            "returnTo", "goto", "destination",
            "continue", "target", "redir",
            "forward", "location", "link"
    );

    private static final List<String> PAYLOADS = List.of(
            PROBE_DOMAIN,
            "//open-redirect-probe.cyberaudit.io"
    );

    private final HttpClient client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    public List<OpenRedirectFinding> scan(String targetUrl, boolean activeMode) {
        List<OpenRedirectFinding> findings = new ArrayList<>();

        if (activeMode) {
            String base = extractBase(targetUrl);
            if (base == null) return findings;

            for (String param : REDIRECT_PARAMS) {
                for (String payload : PAYLOADS) {
                    String testUrl = base + "/?" + param + "=" + encode(payload);
                    OpenRedirectFinding finding = probe(param, testUrl);
                    if (finding != null) {
                        findings.add(finding);
                        break;
                    }
                }
            }
        } else if (targetUrl.contains("?")) {
            findings.addAll(testExistingParams(targetUrl));
        }

        return findings;
    }

    private List<OpenRedirectFinding> testExistingParams(String url) {
        List<OpenRedirectFinding> findings = new ArrayList<>();
        try {
            URI uri = URI.create(url);
            String query = uri.getQuery();
            if (query == null) return findings;

            String base = url.substring(0, url.indexOf('?'));

            for (String part : query.split("&")) {
                String[] kv  = part.split("=", 2);
                String   key = kv[0];

                for (String payload : PAYLOADS) {
                    String testUrl = base + "?" + key + "=" + encode(payload);
                    OpenRedirectFinding finding = probe(key, testUrl);
                    if (finding != null) {
                        findings.add(finding);
                        break;
                    }
                }
            }
        } catch (Exception ignored) {}
        return findings;
    }

    private OpenRedirectFinding probe(String param, String testUrl) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(testUrl))
                    .GET()
                    .timeout(Duration.ofSeconds(6))
                    .header("User-Agent", ScannerHttp.USER_AGENT)
                    .build();

            HttpResponse<Void> resp = client.send(req, HttpResponse.BodyHandlers.discarding());

            int status = resp.statusCode();
            if (status < 300 || status >= 400) return null;

            String location = resp.headers().firstValue("location").orElse("");
            if (location.isBlank()) return null;

            if (!isRedirectingToProbe(location)) return null;

            return new OpenRedirectFinding(param, testUrl, location, true, "HIGH");

        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Verifica se o HOST do Location header é o probe.
     * Evita falsos positivos onde o probe aparece como query param
     * (ex: Google OAuth redireciona para accounts.google.com?continue=<probe>).
     */
    private boolean isRedirectingToProbe(String location) {
        try {
            String normalized = location.startsWith("//")
                    ? "https:" + location
                    : location;

            String decoded = URLDecoder.decode(normalized, StandardCharsets.UTF_8);
            URI redirectUri = URI.create(decoded);
            String host = redirectUri.getHost();

            return host != null && (
                    host.equals("open-redirect-probe.cyberaudit.io") ||
                            host.endsWith(".open-redirect-probe.cyberaudit.io")
            );
        } catch (Exception e) {
            return location.startsWith("https://open-redirect-probe.cyberaudit.io") ||
                    location.startsWith("http://open-redirect-probe.cyberaudit.io")  ||
                    location.startsWith("//open-redirect-probe.cyberaudit.io");
        }
    }

    private String extractBase(String url) {
        try {
            URI uri  = URI.create(url);
            int port = uri.getPort();
            if (port > 0 && port != 80 && port != 443)
                return uri.getScheme() + "://" + uri.getHost() + ":" + port;
            return uri.getScheme() + "://" + uri.getHost();
        } catch (Exception e) {
            return null;
        }
    }

    private String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}