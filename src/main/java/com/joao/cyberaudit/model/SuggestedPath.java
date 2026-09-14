package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Um caminho do mesmo domínio que a página escaneada linka e que merece o próprio
 * scan: login, cadastro, minha-conta, checkout.
 *
 * Existe porque o rótulo é POR PÁGINA. A home de uma loja pode ser vitrine e o
 * /minha-conta dela, não — e o scanner não navega pelo site. Em vez de adivinhar o
 * que há em outra página, a tela sugere escaneá-la.
 */
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class SuggestedPath {

    /** O que a área provavelmente tem: ACCOUNT (login, cadastro) ou PAYMENT (checkout, carrinho). */
    private ImpactLevel level;

    /** Caminho normalizado, para exibir: {@code /minha-conta}. */
    private String path;

    /** URL absoluta, para escanear com um clique. */
    private String url;
}
