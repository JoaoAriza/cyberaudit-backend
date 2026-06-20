package com.joao.cyberaudit.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Relatório de conformidade gerado a partir dos findings de um ScanResult.
 * Mapeia achados para artigos da LGPD e controles ISO 27001:2022.
 */
@Data @Builder @NoArgsConstructor @AllArgsConstructor
public class ComplianceReport {

    /** Score geral de conformidade 0-100 */
    private int overallScore;

    /** Nível de risco: CRITICAL / HIGH / MEDIUM / LOW / COMPLIANT */
    private String riskLevel;

    /** Itens com não-conformidades agrupados por framework */
    private List<ComplianceItem> lgpdItems;
    private List<ComplianceItem> isoItems;

    /** Contagem de status */
    private long lgpdPassed;
    private long lgpdFailed;
    private long isoPassed;
    private long isoFailed;

    @Data @Builder @NoArgsConstructor @AllArgsConstructor
    public static class ComplianceItem {
        /** Ex: "Art. 46" ou "A.10.1" */
        private String reference;
        /** Ex: "Segurança no tratamento de dados" */
        private String title;
        /** Descrição do requisito */
        private String requirement;
        /** PASS | FAIL | WARN | NA */
        private String status;
        /** Achados concretos que violam este controle */
        private List<String> findings;
        /** Recomendação de remediação */
        private String recommendation;
    }
}
