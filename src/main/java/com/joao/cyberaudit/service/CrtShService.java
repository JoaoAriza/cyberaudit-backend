package com.joao.cyberaudit.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

/**
 * Serviço centralizado para consultas a logs de Certificate Transparency.
 *
 * Fonte primária:  crt.sh (via HttpURLConnection — envia % raw sem %25)
 * Fallback:        certspotter.com (SSLMate) — mais estável, sem API key necessária
 *
 * Retorno do certspotter é normalizado para o mesmo schema JSON do crt.sh,
 * então CertTransparencyService e SubdomainTakeoverService não precisam mudar.
 */
@Service
public class CrtShService {

    private static final int  MAX_CERTS       = 200;
    private static final long TTL_SECONDS      = 120;
    private static final int  READ_TIMEOUT_MS  = 20_000;
    private static final int  CONNECT_MS       = 8_000;
    private static final long WAIT_TIMEOUT_S   = 35;

    // certspotter — fallback estável
    private static final String CERTSPOTTER_URL =
            "https://api.certspotter.com/v1/issuances?domain=%s" +
                    "&include_subdomains=true&expand=dns_names&expand=issuer";

    private record CacheEntry(List<JsonNode> certs, Instant fetchedAt) {}

    private final Map<String, CacheEntry>                        cache    = new ConcurrentHashMap<>();
    private final Map<String, CompletableFuture<List<JsonNode>>> inflight = new ConcurrentHashMap<>();
    private final ObjectMapper jackson = new ObjectMapper();

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(8)).build();

    public List<JsonNode> fetchCerts(String host) {
        if (host == null || host.isBlank()) return List.of();

        String rootHost = host.startsWith("www.") ? host.substring(4) : host;

        CacheEntry cached = cache.get(rootHost);
        if (cached != null && Instant.now().isBefore(cached.fetchedAt().plusSeconds(TTL_SECONDS))) {
            return cached.certs();
        }

        // Garante uma única requisição por domínio — chamadas simultâneas aguardam
        CompletableFuture<List<JsonNode>> future = inflight.computeIfAbsent(rootHost, key ->
                CompletableFuture.supplyAsync(() -> {
                    try {
                        List<JsonNode> result = fetchWithFallback(key);
                        cache.put(key, new CacheEntry(result, Instant.now()));
                        return result;
                    } finally {
                        inflight.remove(key);
                    }
                })
        );

        try {
            return future.get(WAIT_TIMEOUT_S, TimeUnit.SECONDS);
        } catch (Exception e) {
            System.out.println("[CrtShService] Timeout waiting for " + rootHost);
            return List.of();
        }
    }

    // ── Fetch com fallback ────────────────────────────────────────────────────

    private List<JsonNode> fetchWithFallback(String host) {
        // 1. Tenta crt.sh
        List<JsonNode> crtSh = fetchFromCrtSh(host);
        if (!crtSh.isEmpty()) return crtSh;

        // 2. Fallback: certspotter
        System.out.println("[CrtShService] crt.sh falhou para " + host + " — tentando certspotter");
        return fetchFromCertspotter(host);
    }

    // ── crt.sh (HttpURLConnection — envia % raw) ──────────────────────────────

    private List<JsonNode> fetchFromCrtSh(String host) {
        String urlStr = "https://crt.sh/?q=%." + host + "&output=json&deduplicate=Y";
        System.out.println("[CrtShService] crt.sh: " + urlStr);
        try {
            URL url = new URL(urlStr);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("User-Agent", "CyberAuditScanner/1.0");
            conn.setRequestProperty("Accept",     "application/json");
            conn.setConnectTimeout(CONNECT_MS);
            conn.setReadTimeout(READ_TIMEOUT_MS);
            conn.setInstanceFollowRedirects(true);

            int status = conn.getResponseCode();
            System.out.println("[CrtShService] crt.sh HTTP " + status + " for " + host);
            if (status != 200) return List.of();

            String body;
            try (InputStream is = conn.getInputStream()) {
                body = new String(is.readAllBytes());
            }
            if (body == null || body.isBlank() || body.trim().startsWith("<")) return List.of();

            JsonNode root = jackson.readTree(body);
            if (!root.isArray()) return List.of();

            List<JsonNode> certs = new ArrayList<>();
            for (JsonNode cert : root) {
                certs.add(cert);
                if (certs.size() >= MAX_CERTS) break;
            }
            System.out.println("[CrtShService] crt.sh → " + certs.size() + " certs para " + host);
            return certs;

        } catch (Exception e) {
            System.out.println("[CrtShService] crt.sh exception: " + e.getMessage());
            return List.of();
        }
    }

    // ── certspotter (fallback estável, HttpClient normal) ─────────────────────

    /**
     * Consulta a API da certspotter.com e normaliza o resultado para o
     * mesmo schema JSON do crt.sh — campos: name_value, issuer_name,
     * not_before, not_after, entry_timestamp, common_name.
     */
    private List<JsonNode> fetchFromCertspotter(String host) {
        try {
            String url = String.format(CERTSPOTTER_URL, host);
            System.out.println("[CrtShService] certspotter: " + url);

            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .GET()
                    .timeout(Duration.ofSeconds(15))
                    .header("User-Agent", "CyberAuditScanner/1.0")
                    .header("Accept",     "application/json")
                    .build();

            HttpResponse<String> resp = httpClient.send(req,
                    HttpResponse.BodyHandlers.ofString());

            System.out.println("[CrtShService] certspotter HTTP " + resp.statusCode() + " for " + host);
            if (resp.statusCode() != 200) return List.of();

            JsonNode root = jackson.readTree(resp.body());
            if (!root.isArray()) return List.of();

            // Normaliza para schema crt.sh
            List<JsonNode> normalized = new ArrayList<>();
            for (JsonNode cert : root) {
                // dns_names → name_value (quebrado por \n como crt.sh)
                List<String> dnsNames = StreamSupport
                        .stream(cert.path("dns_names").spliterator(), false)
                        .map(JsonNode::asText)
                        .collect(Collectors.toList());

                if (dnsNames.isEmpty()) continue;

                String nameValue   = String.join("\n", dnsNames);
                String commonName  = dnsNames.get(0);
                String issuerOrg   = cert.path("issuer").path("name").asText("Unknown");
                String notBefore   = cert.path("not_before").asText("");
                String notAfter    = cert.path("not_after").asText("");

                // Constrói ObjectNode com os campos que CertTransparencyService espera
                ObjectNode node = jackson.createObjectNode();
                node.put("name_value",        nameValue);
                node.put("common_name",        commonName);
                node.put("issuer_name",        "O=" + issuerOrg);
                node.put("not_before",         notBefore);
                node.put("not_after",          notAfter);
                node.put("entry_timestamp",    notBefore);

                normalized.add(node);
                if (normalized.size() >= MAX_CERTS) break;
            }

            System.out.println("[CrtShService] certspotter → " + normalized.size() + " certs para " + host);
            return normalized;

        } catch (Exception e) {
            System.out.println("[CrtShService] certspotter exception: " + e.getMessage());
            return List.of();
        }
    }
}