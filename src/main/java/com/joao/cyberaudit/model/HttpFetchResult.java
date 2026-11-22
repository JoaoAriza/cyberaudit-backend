package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;
import java.util.Map;

@Getter @Setter @AllArgsConstructor @NoArgsConstructor
public class HttpFetchResult {
    private int statusCode;
    private String finalUrl;
    private Map<String, String> headers;
    private List<String> rawSetCookies;
    private String error;

    /**
     * O que a página coleta do visitante, lido do corpo que este fetch já baixa
     * para extrair a CSP de {@code <meta>}. Custo zero: sem o campo, o HTML era
     * usado uma vez e descartado.
     */
    private FormSurfaceResult formSurface;

    /**
     * Nada aceitou a conexão: o domínio não resolveu, a porta recusou, a conexão não
     * abriu a tempo ou não há rota. É diferente de "respondeu com erro" (TLS que falha,
     * servidor que aceita e não responde), em que o alvo existe e está no ar.
     *
     * O orchestrator usa isto para recusar o alvo sem resposta, sem laudo (BUG-16).
     */
    private boolean semConexao;
}
