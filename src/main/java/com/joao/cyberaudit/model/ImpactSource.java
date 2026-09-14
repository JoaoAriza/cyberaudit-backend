package com.joao.cyberaudit.model;

/**
 * De onde veio um sinal de impacto.
 *
 * É o que o plano gratuito enxerga: "a página é sensível por causa dos cookies",
 * sem saber QUAL cookie. Por isso é enum estável, e não texto — a interface
 * traduz e liga cada origem ao módulo correspondente da barra lateral.
 */
public enum ImpactSource {
    /** O HTML da página: formulário, campo de senha, de dado pessoal ou de cartão. */
    FORM,
    /** O caminho da URL: /checkout, /minha-conta. */
    PATH,
    /** Cookie de sessão autenticada. */
    COOKIES,
    /** Token JWT encontrado na resposta. */
    JWT,
    /** Documentação de API exposta (Swagger, OpenAPI). */
    API_DOCS,
    /** Endpoint GraphQL. */
    GRAPHQL
}
