package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.CorsResult;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class CorsAnalyzerService {

    private static final String PROBE_ORIGIN = "https://evil-probe.cyberaudit.io";

    private final HttpFetchService httpFetchService;

    public CorsAnalyzerService(HttpFetchService httpFetchService) {
        this.httpFetchService = httpFetchService;
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
                    "Probe CORS falhou: " + e.getMessage());
        }
    }

    private String buildMessage(boolean wildcard, boolean reflects, boolean credentials,
                                boolean nullAccepted, String acao) {
        if (reflects && credentials)
            return "CORS reflection + credentials: qualquer site faz requests autenticadas cross-origin";
        if (reflects)
            return "CORS reflete a Origin do request — qualquer site acessa seus recursos";
        if (wildcard && credentials)
            return "ACAO: * com ACAC: true — config inválida e insegura";
        if (nullAccepted)
            return "Aceita null origin — acesso via iframe sandboxado ou file://";
        if (acao.isBlank() || "NOT_SET".equals(acao))
            return "Sem CORS headers — padrão seguro (same-origin apenas)";
        return "CORS configurado para origem específica: " + acao;
    }
}