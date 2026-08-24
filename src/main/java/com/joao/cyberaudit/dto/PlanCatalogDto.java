package com.joao.cyberaudit.dto;

import lombok.Builder;
import lombok.Getter;

import java.math.BigDecimal;
import java.util.List;

/**
 * Um plano do cardápio, montado a partir de {@link com.joao.cyberaudit.model.Plan}.
 *
 * Carrega o ESTADO de cada recurso, nunca o texto. O rótulo continua no Frontend,
 * indexado por {@code Feature.id}: o que fez o cardápio mentir foi a matriz de
 * ligado/desligado ficar duplicada em dois repositórios, não a redação. Manter a
 * cópia de marketing em Java só criaria outro lugar para ela envelhecer — e a
 * internacionalização depois teria de tirá-la de lá.
 */
@Getter
@Builder
public class PlanCatalogDto {

    /** FREE, PRO ou ENTERPRISE — o nome da API, não o rótulo de produto. */
    private String plan;

    /** Preço mensal. null no FREE, que não se assina. */
    private BigDecimal amount;
    private String currency;

    private List<Feature> features;

    public enum State {
        /** Liberado sem ressalva. */
        YES,
        /** Não faz parte do plano. */
        NO,
        /**
         * Liberado, mas só sobre domínio verificado da conta — a fronteira do PRO
         * pessoal. O Frontend desenha isto como ◑.
         */
        VERIFIED_DOMAINS_ONLY
    }

    @Getter
    @Builder
    public static class Feature {
        /** Chave estável; o Frontend traduz para rótulo. */
        private String id;
        private State  state;
        /**
         * Quantidade, quando o recurso é contável: -1 = ilimitado.
         * null quando não se aplica (recurso liga/desliga).
         */
        private Integer limit;
    }
}
