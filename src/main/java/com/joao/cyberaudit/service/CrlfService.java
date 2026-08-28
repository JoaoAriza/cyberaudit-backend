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
import java.util.regex.Pattern;

@Service
public class CrlfService {

    /**
     * Header probe injetado — nome e valor únicos para evitar FPs.
     * Confirmação só ocorre se EXATAMENTE este header aparecer na resposta.
     */
    private static final String PROBE_HEADER_NAME  = "X-CyberAudit-Test";
    private static final String PROBE_HEADER_VALUE = "crlf-probe-7x3k";

    /**
     * Linha de status HTTP crua — "HTTP/1.1 200". Dentro do CORPO, é assinatura de
     * resposta partida: nenhuma página legítima serve isso como conteúdo.
     */
    private static final Pattern STATUS_LINE_CRUA =
            Pattern.compile("http/[0-9.]+\\s+[0-9]{3}");

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
     * Testa CRLF injection em modo ativo. Executa dois tipos de probe:
     *
     * 1. Path injection — injeta payload diretamente no path da URL base
     *    (ex: https://example.com/%0d%0aX-CyberAudit-Test:%20crlf-probe-7x3k).
     *    Funciona para qualquer URL, com ou sem query string.
     *
     * 2. Query param injection — se a URL contém query string, injeta o payload
     *    no valor de cada parâmetro individualmente.
     *
     * @param url URL completa (com ou sem query string)
     * @return lista de findings (1 por vetor vulnerável encontrado)
     */
    public List<CrlfFinding> scan(String url) {
        List<CrlfFinding> findings = new ArrayList<>();
        if (url == null || url.isBlank()) return findings;

        // ── 1. Path injection ────────────────────────────────────────────────
        CrlfFinding pathFinding = probePathInjection(url);
        if (pathFinding != null) findings.add(pathFinding);

        // ── 2. Query param injection (só se há parâmetros) ───────────────────
        if (!findings.isEmpty()) return findings; // path já vulnerável, não precisa continuar
        if (url.contains("?")) {
            int q = url.indexOf('?');
            String base  = url.substring(0, q);
            String query = url.substring(q + 1);
            String[] pairs = query.split("&");

            for (String pair : pairs) {
                String[] kv  = pair.split("=", 2);
                String   key = kv[0].trim();
                if (key.isEmpty()) continue;

                CrlfFinding finding = probeParam(base, query, key, pairs);
                if (finding != null) {
                    findings.add(finding);
                    break; // Um finding de parâmetro é suficiente para confirmar a vulnerabilidade
                }
            }
        }

        return findings;
    }

    /**
     * Injeta payloads CRLF diretamente no path da URL.
     * Testa ex: https://example.com/%0d%0aX-CyberAudit-Test:%20crlf-probe-7x3k
     */
    private CrlfFinding probePathInjection(String url) {
        // Remove query string para injetar no path
        String base = url.contains("?") ? url.substring(0, url.indexOf('?')) : url;
        // Remove trailing slash para evitar duplo slash
        if (base.endsWith("/")) base = base.substring(0, base.length() - 1);

        for (String[] payloadEntry : PAYLOADS) {
            String payload       = payloadEntry[0];
            String injectionType = "PATH_" + payloadEntry[1];
            String probeUrl      = base + "/" + payload;

            try {
                HttpRequest req = HttpRequest.newBuilder(URI.create(probeUrl))
                        .GET()
                        .timeout(Duration.ofSeconds(8))
                        .header("User-Agent", ScannerHttp.USER_AGENT)
                        .header("Accept", "text/html,*/*")
                        .build();

                HttpResponse<String> resp = client.send(req,
                        ScannerHttp.limitedString());

                CrlfFinding f = checkProbeInResponse(resp, "path", payload, injectionType);
                if (f != null) return f;

            } catch (Exception ignored) {}
        }
        return null;
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
                        .header("User-Agent", ScannerHttp.USER_AGENT)
                        .header("Accept", "text/html,*/*")
                        .build();

                HttpResponse<String> resp = client.send(req,
                        ScannerHttp.limitedString());

                CrlfFinding f = checkProbeInResponse(resp, paramName, payload, injectionType);
                if (f != null) return f;

            } catch (Exception ignored) {}
        }
        return null;
    }

    /**
     * Verifica se o header probe injetado apareceu nos headers ou body da resposta.
     */
    private CrlfFinding checkProbeInResponse(HttpResponse<String> resp,
                                              String parameter,
                                              String payload,
                                              String injectionType) {
        String headerLower = PROBE_HEADER_NAME.toLowerCase(Locale.ROOT);
        String injected = resp.headers().map().entrySet().stream()
                .filter(e -> e.getKey().toLowerCase(Locale.ROOT).equals(headerLower))
                .flatMap(e -> e.getValue().stream())
                .findFirst()
                .orElse(null);

        if (injected != null && injected.toLowerCase(Locale.ROOT)
                .contains(PROBE_HEADER_VALUE.toLowerCase(Locale.ROOT))) {
            return CrlfFinding.builder()
                    .parameter(parameter)
                    .payload(payload)
                    .injectionType(injectionType)
                    .evidence(PROBE_HEADER_NAME + ": " + injected)
                    .severity("HIGH")
                    .build();
        }

        // ── Probe no CORPO ────────────────────────────────────────────────────
        //
        // Reflexão no corpo, sozinha, NÃO é CRLF injection.
        //
        // Bastava o probe aparecer no corpo para o achado sair como HIGH e descontar
        // 12 pontos. Mas o corpo é onde o servidor ECOA a entrada — é o que qualquer
        // página de erro faz ao dizer "não encontramos /<caminho>". Nesse caso o CRLF
        // não foi interpretado: virou texto dentro do HTML, que é exatamente o
        // contrário do que o achado afirma. Response splitting é sobre a resposta ser
        // PARTIDA, e isso só se prova nos headers.
        //
        // Existe um caso em que o corpo é evidência: quando o split ocorreu de fato e
        // o cliente HTTP passou a ler a resposta injetada como corpo. Aí o corpo traz
        // uma LINHA DE STATUS HTTP crua junto do probe — página nenhuma tem isso. É
        // esse caso, e só ele, que continua valendo.
        String body  = resp.body() == null ? "" : resp.body();
        String lower = body.toLowerCase(Locale.ROOT);

        boolean probeNoCorpo = lower.contains(PROBE_HEADER_VALUE.toLowerCase(Locale.ROOT))
                && lower.contains(headerLower);

        if (probeNoCorpo && STATUS_LINE_CRUA.matcher(lower).find()) {
            return CrlfFinding.builder()
                    .parameter(parameter)
                    .payload(payload)
                    .injectionType(injectionType + "_SPLIT")
                    .evidence("Resposta partida: linha de status HTTP e o header probe "
                            + "aparecem no corpo")
                    .severity("HIGH")
                    .build();
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
