package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.CorsResult;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class CorsAnalyzerService {

    private static final String PROBE_ORIGIN = "https://evil-probe.cyberaudit.io";

    private final HttpFetchService httpFetchService;
    private final MessageCatalog   catalog;

    public CorsAnalyzerService(HttpFetchService httpFetchService, MessageCatalog catalog) {
        this.httpFetchService = httpFetchService;
        this.catalog          = catalog;
    }

    public CorsResult analyze(String url) {
        try {
            Map<String, String> headers = httpFetchService.fetchWithOrigin(url, PROBE_ORIGIN);
            String acao = headers.getOrDefault("access-control-allow-origin", "");
            String acac = headers.getOrDefault("access-control-allow-credentials", "");

            boolean wildcard    = acao.equals("*");
            boolean reflects    = acao.equalsIgnoreCase(PROBE_ORIGIN);
            boolean credentials = acac.equalsIgnoreCase("true");

            Map<String, String> nullHeaders = httpFetchService.fetchWithOrigin(url, "null");
            boolean nullAccepted = nullHeaders
                    .getOrDefault("access-control-allow-origin", "")
                    .equalsIgnoreCase("null");

            return new CorsResult(
                    true,
                    acao.isBlank() ? "NOT_SET" : acao,
                    wildcard, reflects, credentials, nullAccepted,
                    buildMessage(wildcard, reflects, credentials, nullAccepted, acao)
            );

        } catch (Exception e) {
            return new CorsResult(false, "NOT_TESTED", false, false, false, false,
                    catalog.desc("CORS_PROBE_FALHOU", e.getMessage()));
        }
    }

    /**
     * O veredito do CORS, no idioma do laudo.
     *
     * Este texto aparece no card do módulo (e como "Assessment" no PDF, que é
     * monolíngue em inglês) — enquanto era literal, saía em português nos dois.
     */
    private String buildMessage(boolean wildcard, boolean reflects, boolean credentials,
                                boolean nullAccepted, String acao) {
        if (reflects && credentials)
            return catalog.desc("CORS_REFLECTION_CREDENTIALS");
        if (reflects)
            return catalog.desc("CORS_REFLECTION");
        if (wildcard && credentials)
            return catalog.desc("CORS_WILDCARD_CREDENTIALS");
        if (nullAccepted)
            return catalog.desc("CORS_NULL_ORIGIN");
        if (acao.isBlank() || "NOT_SET".equals(acao))
            return catalog.desc("CORS_AUSENTE");
        return catalog.desc("CORS_ORIGEM_ESPECIFICA", acao);
    }
}