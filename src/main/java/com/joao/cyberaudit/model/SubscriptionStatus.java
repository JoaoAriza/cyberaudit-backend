package com.joao.cyberaudit.model;

/**
 * Estado de uma assinatura, espelhando os estados de preapproval do Mercado Pago.
 * PENDING   → criada, aguardando o pagamento/autorização do cliente no checkout.
 * AUTHORIZED→ ativa (pagamento autorizado) → plano liberado.
 * PAUSED    → pausada pelo MP (ex: falha de cobrança) → plano rebaixado.
 * CANCELLED → cancelada (pelo cliente ou admin) → plano rebaixado para FREE.
 */
public enum SubscriptionStatus {
    PENDING,
    AUTHORIZED,
    PAUSED,
    CANCELLED
}
