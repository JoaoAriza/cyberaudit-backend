package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.CrlfFinding;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

@Service
public class CrlfService {

    /**
     * Header probe injetado — nome e valor únicos para evitar FPs.
     * Confirmação só ocorre se EXATAMENTE este header aparecer na resposta.
     */
    private static final String PROBE_HEADER_NAME  = "X-CyberAudit-Test";
    private static final String PROBE_HEADER_VALUE = "crlf-probe-7x3k";

    /**
     * Payloads em ordem de prioridade.
     * { encoded_crlf, tipo }
     * Cada payload injeta o header probe após o CRLF.
     */
    private static final List<String[]> PAYLOADS = List.of(
            // CRLF clássico: %0d%0a
            new String[]{
                "%0d%0a" + PROBE_HEADER_NAME + ":%20" + PROBE_HEADER_VALUE,
                "CRLF_HEADER"
            },
            // LF somente: %0a (suportado por alguns servidores/proxies)
            new String[]{
                "%0a" + PROBE_HEADER_NAME + ":%20" + PROBE_HEADER_VALUE,
                "LF_HEADER"
            },
            // Double URL encoding: %250d%250a (bypassa filtros de primeiro nível)
            new String[]{
                "%250d%250a" + PROBE_HEADER_NAME + ":%20" + PROBE_HEADER_VALUE,
                "DOUBLE_ENCODE"
            },
            // Unicode newline: %E5%98%8D%E5%98%8A (U+560D U+560A — similar a \\r\\n em alguns parsers)
            new String[]{
                "%E5%98%8D%E5%98%8A" + PROBE_HEADER_NAME + ":%20" + PROBE_HEADER_VALUE,
                "UNICODE_CRLF"
            }
    );

    private final HttpClient client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    /**
     * Testa CRLF injection em todos os parâmetros da query string.
     * Só executa em scan ativo quando há surface de input.
     *
     * @param urlWithParams  URL completa com query string
     * @return lista de findings (1 por parâmetro vulnerável)
     */
    public List<CrlfFinding> scan(String urlWithParams) {
        List<CrlfFinding> findings = new ArrayList<>();
        if (urlWithParams == null || !urlWithParams.contains("?")) return findings;

        int q      = urlWithParams.indexOf('?');
        String base  = urlWithParams.substring(0, q);
        String query = urlWithParams.substring(q + 1);
        String[] pairs = query.split("&");

        for (String pair : pairs) {
            String[] kv  = pair.split("=", 2);
            String   key = kv[0].trim();
            if (key.isEmpty()) continue;

            CrlfFinding finding = probeParam(base, query, key, pairs);
            if (finding != null) findings.add(finding);
        }

        return findings;
    }

    private CrlfFinding probeParam(String base, String originalQuery,
                                    String paramName, String[] allPairs) {
        for (String[] payloadEntry : PAYLOADS) {
            String payload       = payloadEntry[0];
            String injectionType = payloadEntry[1];

            // Monta URL com payload raw (sem re-encoding — o payload já está encoded)
            String mutatedQuery = replaceParamValueRaw(allPairs, paramName, payload);
            String url = base + "?" + mutatedQuery;

            try {
                HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                        .GET()
                        .timeout(Duration.ofSeconds(8))
                        .header("User-Agent", "Mozilla/5.0 CyberAuditScanner/1.0")
                        .header("Accept", "text/html,*/*")
                        .build();

                HttpResponse<String> resp = client.send(req,
                        HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));

                // Verifica se o header probe apareceu na resposta
                // Headers HTTP são case-insensitive
                String headerLower = PROBE_HEADER_NAME.toLowerCase(Locale.ROOT);
                String injected = resp.headers().map().entrySet().stream()
                        .filter(e -> e.getKey().toLowerCase(Locale.ROOT).equals(headerLower))
                        .flatMap(e -> e.getValue().stream())
                        .findFirst()
                        .orElse(null);

                if (injected != null && injected.toLowerCase(Locale.ROOT)
                        .contains(PROBE_HEADER_VALUE.toLowerCase(Locale.ROOT))) {
                    return CrlfFinding.builder()
                            .parameter(paramName)
                            .payload(payload)
                            .injectionType(injectionType)
                            .evidence(PROBE_HEADER_NAME + ": " + injected)
                            .severity("HIGH")
                            .build();
                }

                // Fallback: verifica reflexão do probe no body (alguns frameworks
                // refletem headers injetados no corpo da resposta de erro)
                String body = resp.body() == null ? "" : resp.body();
                if (body.toLowerCase(Locale.ROOT).contains(PROBE_HEADER_VALUE.toLowerCase(Locale.ROOT))
                        && body.toLowerCase(Locale.ROOT).contains(PROBE_HEADER_NAME.toLowerCase(Locale.ROOT))) {
                    return CrlfFinding.builder()
                            .parameter(paramName)
                            .payload(payload)
                            .injectionType(injectionType + "_BODY")
                            .evidence("Header probe refletido no body da resposta")
                            .severity("HIGH")
                            .build();
                }

            } catch (Exception ignored) {}
        }
        return null;
    }

    /**
     * Substitui o valor do parâmetro alvo sem re-encodar o payload.
     * O payload já contém os caracteres de encoding necessários.
     */
    private String replaceParamValueRaw(String[] pairs, String targetKey, String newValue) {
        StringBuilder sb = new StringBuilder();
        for (String pair : pairs) {
            if (sb.length() > 0) sb.append('&');
            String[] kv = pair.split("=", 2);
            if (kv[0].equalsIgnoreCase(targetKey)) {
                sb.append(kv[0]).append('=').append(newValue);
            } else {
                sb.append(pair);
            }
        }
        return sb.toString();
    }
}
