package com.joao.cyberaudit.service;

import com.joao.cyberaudit.exception.DomainBlockedException;
import com.joao.cyberaudit.model.HttpFetchResult;
import com.joao.cyberaudit.model.RelatedHostHeaders;
import org.springframework.stereotype.Service;

import java.net.InetAddress;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.*;
import java.util.stream.Collectors;

/**
 * Audita os headers de segurança de hosts relacionados ao alvo (escopo focado:
 * prefixos com cara de app/API). Ex: ao escanear exemplo.com, também olha
 * api.exemplo.com, server.exemplo.com, etc.
 *
 * Informativo: não entra no score do host principal.
 */
@Service
public class RelatedHostsHeaderService {

    /** Prefixos com cara de aplicação/API — escopo focado para custo baixo. */
    private static final List<String> APP_PREFIXES = List.of(
            "www", "api", "server", "app", "admin", "portal", "auth", "backend"
    );
    private static final int MAX_HOSTS = 6;

    private final HttpFetchService    httpFetchService;
    private final HeaderService       headerService;
    private final PublicSuffixService publicSuffixService;

    public RelatedHostsHeaderService(HttpFetchService httpFetchService, HeaderService headerService,
                                     PublicSuffixService publicSuffixService) {
        this.httpFetchService    = httpFetchService;
        this.headerService       = headerService;
        this.publicSuffixService = publicSuffixService;
    }

    public List<RelatedHostHeaders> analyze(String scannedHost) {
        if (scannedHost == null || scannedHost.isBlank()) return List.of();

        // Base = domínio registrável (apex) via Public Suffix List. Funciona para
        // subdomínios profundos (app.deep.site.com → site.com) e sufixos multi-label
        // (www.site.com.br → site.com.br). Fallback para o host se não houver registrável.
        String base = publicSuffixService.registrableDomain(scannedHost);
        if (base == null) base = scannedHost;

        // Candidatos = prefixos + base, exceto o host já analisado no fluxo principal.
        LinkedHashSet<String> candidates = new LinkedHashSet<>();
        for (String p : APP_PREFIXES) {
            String h = p + "." + base;
            if (!h.equalsIgnoreCase(scannedHost)) candidates.add(h);
        }

        List<String> toProbe = candidates.stream().limit(MAX_HOSTS).collect(Collectors.toList());
        if (toProbe.isEmpty()) return List.of();

        ExecutorService pool = Executors.newFixedThreadPool(Math.min(toProbe.size(), 6));
        try {
            List<CompletableFuture<RelatedHostHeaders>> futures = toProbe.stream()
                    .map(h -> CompletableFuture.supplyAsync(() -> probe(h), pool).exceptionally(e -> null))
                    .collect(Collectors.toList());

            try {
                CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                        .get(20, TimeUnit.SECONDS);
            } catch (Exception ignored) {}

            return futures.stream()
                    .map(f -> f.getNow(null))
                    .filter(Objects::nonNull)
                    .collect(Collectors.toList());
        } finally {
            pool.shutdownNow();
        }
    }

    private RelatedHostHeaders probe(String host) {
        // Resolve rápido — pula subdomínios inexistentes sem pagar timeout de conexão.
        try { InetAddress.getByName(host); }
        catch (Exception e) { return null; }

        String url = "https://" + host;

        // Anti-SSRF: não buscar hosts que apontem para rede interna (mesma proteção do alvo).
        try { SsrfGuard.validate(url); }
        catch (DomainBlockedException e) { return null; }

        HttpFetchResult fetch = httpFetchService.fetchHeaders(url);
        if (fetch.getError() != null) return null;  // inacessível → não reportar

        Map<String, String> analyzed = headerService.analyzeSecurityHeaders(fetch.getHeaders());
        int missing = (int) analyzed.values().stream()
                .filter(v -> v != null && v.startsWith("MISSING"))
                .count();

        return RelatedHostHeaders.builder()
                .host(host)
                .reachable(true)
                .headers(analyzed)
                .missingCount(missing)
                .build();
    }
}
