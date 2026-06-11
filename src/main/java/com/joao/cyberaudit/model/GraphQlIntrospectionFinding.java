package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GraphQlIntrospectionFinding {

    /** Endpoint onde GraphQL foi detectado: ex "/graphql", "/api/graphql" */
    private String endpoint;

    /**
     * Introspection habilitada em producao.
     * A query { __schema { types { name } } } retornou o schema completo.
     * Expoe todos os tipos, queries, mutations e subscriptions da API.
     */
    private boolean introspectionEnabled;

    /**
     * Interface interativa (GraphiQL ou GraphQL Playground) acessivel publicamente.
     * Permite explorar e executar queries sem autenticacao.
     */
    private boolean playgroundExposed;

    /**
     * Numero de tipos no schema (extraido da resposta de introspection).
     * -1 se nao foi possivel extrair.
     */
    private int typeCount;

    /** "HIGH" se playground exposto, "MEDIUM" se so introspection, "LOW" se so detectado */
    private String severity;

    /** Trecho da resposta que confirmou a deteccao */
    private String evidence;
}
