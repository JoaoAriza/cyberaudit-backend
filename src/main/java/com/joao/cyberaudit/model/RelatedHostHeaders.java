package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Map;

/**
 * Postura de headers de segurança de um host RELACIONADO ao alvo (ex: api., server., www.).
 *
 * Informativo: aparece em painel próprio, NÃO entra no score do host principal — pode
 * ser infraestrutura de terceiros (CDN) ou host que o usuário não controla diretamente.
 */
@Getter @Setter @Builder @AllArgsConstructor @NoArgsConstructor
public class RelatedHostHeaders {

    /** Host relacionado analisado (ex: server.exemplo.com). */
    private String host;

    /** Respondeu à requisição (resolveu DNS e retornou resposta). */
    private boolean reachable;

    /** Análise dos headers de segurança (MISSING/OK/WEAK), mesmo formato do host principal. */
    private Map<String, String> headers;

    /** Quantidade de headers de segurança ausentes (MISSING). */
    private int missingCount;
}
