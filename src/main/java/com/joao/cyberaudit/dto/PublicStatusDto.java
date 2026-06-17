package com.joao.cyberaudit.dto;

import java.util.List;

/**
 * Payload retornado pelo endpoint público /public/status/{token}.
 * Nunca expõe dados internos (IDs, emails, tokens).
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
            List<IssueDto> topIssues
    ) {}

    public record IssueDto(
            String severity,
            String title,
            String recommendation
    ) {}
}
