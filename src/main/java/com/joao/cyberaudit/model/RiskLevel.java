package com.joao.cyberaudit.model;

/**
 * Níveis de risco do score de segurança.
 *
 * Thresholds (produzidos pelo ScoreService):
 *   SECURE   ≥ 85  — configuração sólida, issues menores ou nenhum
 *   LOW      ≥ 70  — alguns problemas de configuração, sem vulns exploráveis
 *   MEDIUM   ≥ 45  — problemas notáveis que devem ser corrigidos
 *   HIGH     ≥ 20  — vulnerabilidades significativas com potencial de exploração
 *   CRITICAL < 20  — vulnerabilidades críticas / exploráveis confirmadas
 *
 * Nota: WARNING mantido apenas para compatibilidade com registros históricos.
 * O ScoreService não produz WARNING — registros antigos são mapeados como MEDIUM
 * pela camada de apresentação.
 */
public enum RiskLevel {
    SECURE,
    LOW,
    MEDIUM,
    WARNING,   // @deprecated — alias legado, equivalente a MEDIUM
    HIGH,
    CRITICAL
}
