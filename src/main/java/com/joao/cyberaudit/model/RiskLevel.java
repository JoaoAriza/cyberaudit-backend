package com.joao.cyberaudit.model;

/**
 * Níveis de risco do score de segurança.
 *
 * Thresholds:
 *   SECURE   ≥ 85  — configuração sólida, issues menores ou nenhum
 *   LOW      ≥ 70  — alguns problemas de configuração, sem vulns exploráveis
 *   MEDIUM   ≥ 45  — problemas notáveis que devem ser corrigidos
 *   HIGH     ≥ 20  — vulnerabilidades significativas com potencial de exploração
 *   CRITICAL < 20  — vulnerabilidades críticas / exploráveis confirmadas
 *
 * Override por severidade de findings:
 *   Se existir qualquer SecurityIssue CRITICAL → risco mínimo HIGH
 *   Se existir qualquer SecurityIssue HIGH     → risco mínimo MEDIUM
 */
public enum RiskLevel {
    SECURE,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}
