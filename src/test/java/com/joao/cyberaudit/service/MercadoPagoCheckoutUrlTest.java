package com.joao.cyberaudit.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * A limpeza do init_point de criação.
 *
 * O caso real: POST /preapproval devolveu
 * {@code https://www.mercadopago.com.br/subscriptions/checkout?preapproval_id=X&activation=true},
 * e essa URL respondia "esta página não existe". A mesma sem {@code activation} — que é
 * o que o GET do MESMO preapproval devolvia — abria o checkout nas duas abas
 * (logado e não logado no Mercado Pago). O app usava a de criação e mandava o
 * cliente para o 404.
 */
class MercadoPagoCheckoutUrlTest {

    private static final String CHECKOUT =
            "https://www.mercadopago.com.br/subscriptions/checkout?preapproval_id=3b6e4b70d7804df5bb546a571bed16f8";

    @Test
    @DisplayName("remove activation=true no fim da query, preservando o resto")
    void removeActivationNoFim() {
        assertEquals(CHECKOUT, MercadoPagoService.checkoutUtilizavel(CHECKOUT + "&activation=true"));
    }

    @Test
    @DisplayName("remove activation no meio da query")
    void removeActivationNoMeio() {
        String entrada = "https://www.mercadopago.com.br/subscriptions/checkout?activation=true&preapproval_id=X";
        assertEquals("https://www.mercadopago.com.br/subscriptions/checkout?preapproval_id=X",
                MercadoPagoService.checkoutUtilizavel(entrada));
    }

    @Test
    @DisplayName("activation como único parâmetro deixa a URL sem query")
    void activationSozinho() {
        assertEquals("https://www.mercadopago.com.br/subscriptions/checkout",
                MercadoPagoService.checkoutUtilizavel(
                        "https://www.mercadopago.com.br/subscriptions/checkout?activation=true"));
    }

    @Test
    @DisplayName("URL já limpa não é alterada")
    void semActivationNaoMuda() {
        assertEquals(CHECKOUT, MercadoPagoService.checkoutUtilizavel(CHECKOUT));
    }

    @Test
    @DisplayName("não confunde outro parâmetro que contém 'activation' no valor")
    void naoRemoveParametroParecido() {
        String entrada = CHECKOUT + "&reactivation_hint=true";
        assertEquals(entrada, MercadoPagoService.checkoutUtilizavel(entrada),
                "só o parâmetro chamado 'activation' sai; 'reactivation_hint' fica");
    }

    @Test
    @DisplayName("nulo e sem query não quebram")
    void bordas() {
        assertNull(MercadoPagoService.checkoutUtilizavel(null));
        assertEquals("https://www.mercadopago.com.br/x",
                MercadoPagoService.checkoutUtilizavel("https://www.mercadopago.com.br/x"));
    }
}
