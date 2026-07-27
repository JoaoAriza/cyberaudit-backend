package com.joao.cyberaudit.model;

/**
 * Ciclo de vida de um feedback (contestação de achado).
 * OPEN      → recém-enviado pelo cliente, aguardando triagem.
 * REVIEWING → admin está analisando / em debate com o cliente.
 * RESOLVED  → triagem concluída (procede ou é falso-positivo confirmado).
 */
public enum FeedbackStatus {
    OPEN,
    REVIEWING,
    RESOLVED
}
