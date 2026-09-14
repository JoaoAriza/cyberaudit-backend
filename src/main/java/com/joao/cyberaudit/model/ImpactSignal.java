package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Um motivo do rótulo de impacto: a origem e o que casou.
 *
 * Existe para o rótulo poder ser defendido na frente do cliente — "PAGAMENTO"
 * sozinho é afirmação; "PAGAMENTO porque a página tem campo de cartão" é laudo.
 */
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class ImpactSignal {

    private ImpactSource source;

    /**
     * O que casou: código do marcador de formulário ({@code payment-field}), o
     * segmento do caminho ({@code /checkout}), o nome do cookie, o endpoint.
     *
     * Nulo na cópia entregue a guest/FREE — é justamente o "porquê" que o plano
     * gratuito não recebe.
     */
    private String detail;
}
