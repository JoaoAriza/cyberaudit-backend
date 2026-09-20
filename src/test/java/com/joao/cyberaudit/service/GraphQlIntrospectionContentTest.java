package com.joao.cyberaudit.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.support.ResourceBundleMessageSource;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A decisão de "isto é um achado?" a partir do CONTEÚDO da resposta.
 *
 * O módulo não reporta um {@code /graphql} por ele existir: sonda o endpoint e lê a
 * resposta. Um endpoint com introspection desligada existe e responde, mas não expõe
 * nada — e é o alvo BEM configurado, que não pode virar achado. Estes testes fixam
 * essa leitura, sem rede, pelos dois métodos visíveis ao pacote.
 *
 * O caso que mais importa é o do Apollo: com introspection desligada, ele responde um
 * erro que CITA a palavra {@code __schema}. Um match ingênuo por texto acusaria schema
 * exposto onde o servidor está justamente recusando.
 */
class GraphQlIntrospectionContentTest {

    private GraphQlIntrospectionService servico() {
        var fonte = new ResourceBundleMessageSource();
        fonte.setBasename("messages");
        fonte.setDefaultEncoding("UTF-8");
        fonte.setFallbackToSystemLocale(false);
        return new GraphQlIntrospectionService(new MessageCatalog(fonte));
    }

    private boolean confirma(int status, String contentType, String body) {
        return servico().introspectionConfirmed(status, contentType, body.toLowerCase());
    }

    // ── Não é achado: endpoint existe, mas não devolve schema ────────────────

    @Test
    @DisplayName("\"No query string was present\" não é schema exposto")
    void erroDeQueryAusenteNaoEhAchado() {
        // Exatamente a tela que motivou isto: o GET/POST sem query devolve um erro,
        // não o schema.
        assertFalse(confirma(200, "application/json",
                "{\"errors\":[{\"message\":\"No query string was present\"}]}"));
    }

    @Test
    @DisplayName("erro do Apollo que CITA __schema não conta como schema exposto")
    void apolloIntrospectionDesligadaNaoEhAchado() {
        // A palavra __schema aparece no texto do erro, mas sem aspas de CHAVE. É o
        // falso positivo clássico de quem procura só o texto.
        String apollo = "{\"errors\":[{\"message\":\"GraphQL introspection is not allowed "
                + "by Apollo Server, but the query contained __schema or __type. To enable "
                + "introspection, pass introspection: true to ApolloServer in production\"}]}";
        assertFalse(confirma(200, "application/json", apollo),
                "erro que cita __schema não é schema devolvido");
    }

    @Test
    @DisplayName("200 com o schema em HTML (não-JSON) não confirma pela via da API")
    void corpoHtmlNaoConfirmaIntrospection() {
        // A UI é decidida pelo playgroundMarker; a via da API exige JSON.
        assertFalse(confirma(200, "text/html",
                "<html><body>__schema types</body></html>"));
    }

    @Test
    @DisplayName("resposta autenticada (401/403) não é schema exposto, mesmo parecendo schema")
    void statusNao200NaoConfirma() {
        String comSchema = "{\"data\":{\"__schema\":{\"types\":[{\"name\":\"Query\"}]}}}";
        assertFalse(confirma(401, "application/json", comSchema));
        assertFalse(confirma(403, "application/json", comSchema));
        assertFalse(confirma(400, "application/json", comSchema));
    }

    @Test
    @DisplayName("só __schema, sem types, não confirma — as duas chaves são exigidas")
    void schemaSemTypesNaoConfirma() {
        assertFalse(confirma(200, "application/json",
                "{\"data\":{\"__schema\":null}}"));
    }

    // ── É achado: schema de fato devolvido ───────────────────────────────────

    @Test
    @DisplayName("schema devolvido, com as duas chaves entre aspas, confirma")
    void schemaDevolvidoConfirma() {
        String real = "{\"data\":{\"__schema\":{\"types\":[{\"name\":\"Query\"},"
                + "{\"name\":\"User\"}]}}}";
        assertTrue(confirma(200, "application/json", real));
    }

    @Test
    @DisplayName("JSON sem content-type declarado ainda confirma pelo corpo entre chaves")
    void jsonSemContentTypeConfirmaPeloCorpo() {
        String real = "{\"data\":{\"__schema\":{\"types\":[{\"name\":\"Query\"}]}}}";
        assertTrue(confirma(200, "", real));
    }

    // ── Playground: só HTML com o asset da ferramenta ────────────────────────

    @Test
    @DisplayName("JSON de erro no GET não é playground — playground é UI em HTML")
    void jsonNoGetNaoEhPlayground() {
        assertNull(servico().playgroundMarker(
                "{\"errors\":[{\"message\":\"no query string was present\"}]}",
                "application/json"));
    }

    @Test
    @DisplayName("HTML que monta o GraphiQL é playground exposto")
    void htmlDoGraphiqlEhPlayground() {
        String html = "<!doctype html><html><body><div id=\"graphiql\"></div>"
                + "<script src=\"/graphiql.min.js\"></script></body></html>";
        assertTrue(servico().playgroundMarker(html.toLowerCase(), "text/html") != null);
    }
}
