package com.joao.cyberaudit.model;

/**
 * Por que o rótulo de impacto não foi determinado.
 *
 * O rótulo só afirma o que viu nos campos da página. Quando não viu, diz o motivo
 * em vez de chutar — o palpite pelo endereço fez de uma tela de login bloqueada
 * (petz.com.br/checkout/login, HTTP 403) um PAGAMENTO.
 */
public enum ImpactUndetermined {

    /** Resposta fora de 2xx: bloqueio de WAF, erro, página inexistente. */
    HTTP_STATUS,

    /** Resposta 2xx sem HTML para ler. */
    EMPTY,

    /** Aplicação JavaScript: os campos só existem depois de executar o script. */
    JS_RENDERED
}
