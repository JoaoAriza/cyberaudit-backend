package com.joao.cyberaudit.model;

/**
 * Estado de uma assinatura, espelhando os estados de preapproval do Mercado Pago.
 * PENDING   → criada, aguardando o pagamento/autorização do cliente no checkout.
 * AUTHORIZED→ ativa (pagamento autorizado) → plano liberado.
 * PAUSED    → pausada pelo MP (ex: falha de cobrança) → plano rebaixado.
 * CANCELLED → cancelada (pelo cliente ou admin) → plano rebaixado para FREE.
 * EXPIRED   → só para PaymentMethod.PIX: currentPeriodEnd passou sem um pagamento
 *             novo confirmado → plano rebaixado para FREE pelo job diário.
 */
public enum SubscriptionStatus {
    PENDING,
    AUTHORIZED,
    PAUSED,
    CANCELLED,
    EXPIRED
}
