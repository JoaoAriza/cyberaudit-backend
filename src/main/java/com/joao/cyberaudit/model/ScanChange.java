package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ScanChange {

    /**
     * Categoria do que mudou.
     * Ex: SSL, HEADERS, PORTS, SCORE, WAF, DNS, METHODS, TECH, FILES
     */
    private String category;

    /**
     * Campo específico dentro da categoria.
     * Ex: "Strict-Transport-Security", "port 22", "score", "DMARC policy"
     */
    private String field;

    /**
     * Tipo de mudança.
     * ADDED     → algo novo apareceu (ex: nova porta aberta)
     * REMOVED   → algo desapareceu (ex: header sumiu)
     * IMPROVED  → mudança positiva (ex: score subiu, header adicionado)
     * DEGRADED  → mudança negativa (ex: score caiu, certificado expirando)
     * CHANGED   → mudou sem valência clara (ex: versão de software alterada)
     */
    private String changeType;

    private String oldValue;
    private String newValue;

    /** CRITICAL, HIGH, MEDIUM, LOW, INFO */
    private String severity;

    /** Descrição legível para o analista */
    private String description;
}