package com.joao.cyberaudit.model;

/**
 * O que há para perder nesta página — eixo separado do score.
 *
 * O score responde "quão frágil está a configuração"; este rótulo responde "o
 * que está em jogo". Sem ele, uma vitrine que só leva ao WhatsApp e um checkout
 * saem com a mesma nota e a mesma cor, e um achado sem consequência real se
 * apresenta com o mesmo peso de um vazamento de dado de cliente.
 *
 * Deliberadamente NÃO entra no cálculo do score: mexer na nota quebraria as
 * séries históricas e a detecção de mudança por caminho. É metadado ao lado,
 * nunca dentro.
 *
 * A ordem das constantes é a escala — o nível mais alto que casar vence.
 */
public enum ImpactLevel {

    /** Informativo. Não coleta nada: sem formulário, sem sessão, sem conta. */
    SHOWCASE,

    /** Coleta dado pessoal sem autenticar: formulário de contato, e-mail, CPF. */
    CONTACT,

    /** Tem área autenticada: sessão, login, token. */
    ACCOUNT,

    /** Trata pagamento: checkout, campo de cartão, plataforma de e-commerce. */
    PAYMENT
}
