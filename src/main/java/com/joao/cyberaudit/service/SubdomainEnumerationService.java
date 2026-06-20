package com.joao.cyberaudit.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.joao.cyberaudit.dto.SubdomainInfo;
import org.springframework.stereotype.Service;

import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

/**
 * Enumera subdomínios de um domínio raiz usando:
 *  1. Certificate Transparency logs (via CrtShService — crt.sh / certspotter)
 *  2. DNS resolution para verificar se cada subdomínio está ativo
 *  3. HTTP probe (HEAD) para obter o status code
 *
 * Disponível apenas para contas EMPRESA (COMPANY).
 */
@Service
public class SubdomainEnumerationService {

    private static final int MAX_TO_PROBE  = 80;   // máximo de subdomínios a sondar
    private static final int PROBE_TIMEOUT = 6;    // segundos por probe HTTP
    private static final int THREAD_POOL   = 15;   // paralelismo máximo

    private final CrtShService crtShService;

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();

    public SubdomainEnumerationService(CrtShService crtShService) {
        this.crtShService = crtShService;
    }

    /**
     * Enumera subdomínios do domínio raiz fornecido.
     *
     * @param rootHost domínio raiz normalizado (ex: "empresa.com.br")
     * @return lista de subdomínios descobertos, vivos primeiro
     */
    public List<SubdomainInfo> enumerate(String rootHost) {
        // 1. Coleta todos os nomes do CT log
        List<JsonNode> certs = crtShService.fetchCerts(rootHost);
        Set<String> candidates = extractSubdomains(certs, rootHost);

        System.out.printf("[SubdomainEnum] %d candidatos para %s%n", candidates.size(), rootHost);

        // 2. Limita e probe em paralelo
        List<String> toProbe = candidates.stream()
                .sorted()
                .limit(MAX_TO_PROBE)
                .toList();

        ExecutorService pool = Executors.newFixedThreadPool(THREAD_POOL);
        List<Future<SubdomainInfo>> futures = toProbe.stream()
                .map(host -> pool.submit(() -> probe(host)))
                .toList();

        List<SubdomainInfo> results = new ArrayList<>();
        for (Future<SubdomainInfo> f : futures) {
            try { results.add(f.get(PROBE_TIMEOUT + 2, TimeUnit.SECONDS)); }
            catch (Exception e) { /* skip timeout */ }
        }
        pool.shutdownNow();

        // 3. Ordena: vivos primeiro, depois alfabético
        results.sort(Comparator
                .comparing(SubdomainInfo::alive).reversed()
                .thenComparing(SubdomainInfo::host));

        System.out.printf("[SubdomainEnum] %d resultados (vivos: %d) para %s%n",
                results.size(),
                results.stream().filter(SubdomainInfo::alive).count(),
                rootHost);

        return results;
    }

    // ── Extração de nomes do CT log ───────────────────────────────────────────

    private Set<String> extractSubdomains(List<JsonNode> certs, String rootHost) {
        Set<String> result = new LinkedHashSet<>();
        String suffix = "." + rootHost;

        for (JsonNode cert : certs) {
            String nameValue = cert.path("name_value").asText("");
            // name_value pode ter múltiplos nomes separados por \n
            for (String raw : nameValue.split("[\\n,]")) {
                String name = raw.trim().toLowerCase();
                if (name.isEmpty()) continue;

                // Remove wildcards — guarda só o parte fixa
                if (name.startsWith("*.")) name = name.substring(2);

                // Deve ser subdomínio do rootHost (não o próprio)
                if (name.equals(rootHost)) continue;
                if (!name.endsWith(suffix)) continue;

                result.add(name);
            }
        }
        return result;
    }

    // ── Probe individual (DNS + HTTP) ─────────────────────────────────────────

    private SubdomainInfo probe(String host) {
        // DNS resolution
        String ip = null;
        try {
            InetAddress addr = InetAddress.getByName(host);
            ip = addr.getHostAddress();
        } catch (Exception e) {
            // DNS não resolveu — subdomínio inativo
            return new SubdomainInfo(host, false, null, null);
        }

        // HTTP probe
        Integer status = httpProbe(host);
        return new SubdomainInfo(host, true, status, ip);
    }

    private Integer httpProbe(String host) {
        // Tenta HTTPS primeiro, depois HTTP
        for (String scheme : List.of("https", "http")) {
            try {
                HttpRequest req = HttpRequest.newBuilder()
                        .uri(URI.create(scheme + "://" + host + "/"))
                        .method("HEAD", HttpRequest.BodyPublishers.noBody())
                        .timeout(Duration.ofSeconds(PROBE_TIMEOUT))
                        .header("User-Agent", "CyberAuditScanner/1.0")
                        .build();

                HttpResponse<Void> resp = httpClient.send(req,
                        HttpResponse.BodyHandlers.discarding());
                return resp.statusCode();
            } catch (Exception ignored) {}
        }
        return null; // respondeu ao DNS mas não ao HTTP
    }
}
