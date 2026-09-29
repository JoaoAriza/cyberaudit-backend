package com.joao.cyberaudit.model;

/**
 * Meio de pagamento de uma {@link Subscription}.
 *
 * CARD é recorrente de verdade: o Mercado Pago debita sozinho a cada ciclo via
 * preapproval, e o status vem do webhook de preapproval.
 *
 * PIX não tem débito automático (Pix comum é pagamento único) — cada ciclo exige
 * um novo pagamento, e {@link Subscription#getCurrentPeriodEnd()} marca até quando
 * o plano liberado por aquele pagamento continua válido. Um job diário rebaixa a
 * conta quando o período vence sem um pagamento novo confirmado.
 */
public enum PaymentMethod {
    CARD,
    PIX
}
