package com.joao.cyberaudit.dto;

import java.util.List;

/**
 * Payload retornado pelo endpoint público /public/status/{token}.
 * Nunca expõe dados internos (IDs, emails, tokens).
 *
 * <h2>Por que aqui vai contagem por severidade, e não a lista de achados</h2>
 *
 * Esta página existe para transmitir confiança: "somos monitorados, e este é o
 * nosso score". A versão anterior publicava os 5 principais achados ordenados do
 * pior para o melhor, com título E o texto de correção — ou seja, entregava a
 * quem abrisse o link uma lista priorizada das vulnerabilidades ainda não
 * corrigidas, junto com a descrição do que estava errado. Uma página de confiança
 * virava roteiro de ataque, e o link é feito para ser compartilhado.
 *
 * A contagem por severidade preserva o sinal inteiro (dá para ver que existem 2
 * MEDIUM em aberto e acompanhar a evolução) sem dizer QUAIS são nem COMO explorar.
 *
 * Efeito colateral bem-vindo: este endpoint é público e não passa pelo
 * ScanEntitlementService, então antes ele devolvia título e correção — exatamente
 * os campos que o plano FREE não vê na própria interface.
 */
public record PublicStatusDto(
        String  accountName,
        String  plan,
        String  generatedAt,
        int     overallScore,
        String  overallRisk,
        List<DomainStatusDto> domains
) {
    public record DomainStatusDto(
            String  host,
            boolean verified,
            Integer score,
            String  riskLevel,
            String  lastScanAt,
            boolean activeMode,
            IssueCountsDto issueCounts
    ) {}

    /** Quantos achados em aberto por severidade — sem título e sem correção. */
    public record IssueCountsDto(
            long critical,
            long high,
            long medium,
            long low
    ) {
        public static final IssueCountsDto EMPTY = new IssueCountsDto(0, 0, 0, 0);
    }
}
