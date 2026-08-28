package com.joao.cyberaudit.service;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.ResourceBundleMessageSource;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Mencionar a ferramenta não é servir a ferramenta.
 *
 * Três módulos confirmavam achado quando o corpo da resposta apenas CITAVA o nome do
 * que procuravam. O cliente descobriu escaneando o github.com, onde as três coisas são
 * páginas de perfil de usuários e organizações:
 *
 * <ul>
 *   <li>{@code /swagger-ui.html} — perfil do usuário "swagger-ui". A regra era
 *       "é HTML e contém a string swagger-ui": o nome aparece 47 vezes ali;</li>
 *   <li>{@code /graphql} — perfil da organização GraphQL. O marcador era a palavra
 *       "graphiql", que aparece 14 vezes porque é o nome de um repositório;</li>
 *   <li>CRLF — bastava o probe voltar no CORPO. Corpo é onde o servidor ECOA a
 *       entrada; response splitting se prova nos headers.</li>
 * </ul>
 *
 * Somados, os três descontavam 26 pontos de um site que não tem nenhum dos problemas.
 *
 * O CRLF é exercitado ponta a ponta contra um servidor HTTP local, porque ele usa o
 * próprio cliente. Swagger e GraphQL passam pelo {@code ScannerHttp}, que valida no
 * {@code SsrfGuard} e recusa 127.0.0.1: um teste por servidor local ali passaria com a
 * requisição BLOQUEADA, sem provar nada sobre a decisão. Por isso esses dois chamam a
 * função de decisão direto. Nenhum toca a rede.
 */
class ProbeFalsePositiveTest {

    private HttpServer server;

    /** Sobe um servidor que decide a resposta a partir do caminho pedido. */
    private String sobeServidor(Function<HttpExchange, String> resposta) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", troca -> {
            byte[] corpo = resposta.apply(troca).getBytes(StandardCharsets.UTF_8);
            troca.getResponseHeaders().add("Content-Type", "text/html; charset=utf-8");
            troca.sendResponseHeaders(200, corpo.length);
            troca.getResponseBody().write(corpo);
            troca.close();
        });
        server.start();
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterEach
    void derruba() {
        if (server != null) server.stop(0);
    }

    // ── Swagger UI ───────────────────────────────────────────────────────────

    /** Recorte fiel do perfil github.com/swagger-ui: HTML que só CITA o nome. */
    private static final String PERFIL_SWAGGER = """
            <!DOCTYPE html><html lang="en">
            <head><title>swagger-ui · GitHub</title></head>
            <body><h1>swagger-ui</h1>
              <a href="/swagger-ui/swagger-ui">swagger-ui/swagger-ui</a>
              <p>The official Swagger UI repository</p>
            </body></html>
            """;

    /** Página real do Swagger UI: carrega os assets dele e monta no próprio nó. */
    private static final String SWAGGER_REAL = """
            <!DOCTYPE html><html><head>
              <link rel="stylesheet" href="./swagger-ui.css">
            </head><body>
              <div id="swagger-ui"></div>
              <script src="./swagger-ui-bundle.js"></script>
              <script>window.ui = SwaggerUIBundle({ url: "/v3/api-docs" });</script>
            </body></html>
            """;

    // Estes dois serviços passam pelo ScannerHttp, que valida no SsrfGuard e recusa
    // 127.0.0.1 — um servidor de teste local nunca seria consultado, e o teste
    // "passaria" com a requisição bloqueada, provando nada. Exercitam a DECISÃO direto.
    /** Catálogo real: a evidência sai dele, então o teste também confere o texto. */
    private MessageCatalog catalogo() {
        var source = new ResourceBundleMessageSource();
        source.setBasename("messages");
        source.setDefaultEncoding("UTF-8");
        source.setFallbackToSystemLocale(false);
        return new MessageCatalog(source);
    }

    private String swagger(String html) {
        return new ApiDocsExposureService(catalogo())
                .matchEvidence("SWAGGER_UI", html.toLowerCase(), "text/html");
    }

    private String playground(String html) {
        return new GraphQlIntrospectionService(catalogo())
                .playgroundMarker(html.toLowerCase(), "text/html");
    }

    @Test
    @DisplayName("página que só cita swagger-ui não é Swagger UI — o caso github.com/swagger-ui.html")
    void perfilQueCitaSwaggerNaoEAchado() {
        assertNull(swagger(PERFIL_SWAGGER),
                "citar o nome 47 vezes não põe um Swagger UI no ar");
    }

    @Test
    @DisplayName("Swagger UI de verdade continua sendo detectado")
    void swaggerRealViraAchado() {
        assertNotNull(swagger(SWAGGER_REAL),
                "assets e container do Swagger UI provam que ele está servido ali");
    }

    @Test
    @DisplayName("cada marcador forte do Swagger confirma sozinho")
    void marcadoresFortesDoSwagger() {
        assertNotNull(swagger("<html><script src='swagger-ui-bundle.js'></script></html>"));
        assertNotNull(swagger("<html><link href='swagger-ui.css'></html>"));
        assertNotNull(swagger("<html><div id=\"swagger-ui\"></div></html>"));
        // Spec embutida: é a definição da API, não uma menção ao nome.
        assertNotNull(swagger("{\"swagger\":\"2.0\",\"paths\":{\"/users\":{}}}"));
    }

    // ── GraphQL playground ───────────────────────────────────────────────────

    @Test
    @DisplayName("página que só cita graphiql não é playground — o caso github.com/graphql")
    void perfilQueCitaGraphiqlNaoEAchado() {
        assertNull(playground("""
                <!DOCTYPE html><html><head><title>GraphQL · GitHub</title></head>
                <body><h1>graphql</h1>
                  <a href="/graphql/graphiql">graphql/graphiql</a>
                  <p>GraphiQL is a reference implementation of a GraphQL IDE</p>
                </body></html>
                """), "o nome do repositório não é uma UI interativa exposta");
    }

    @Test
    @DisplayName("GraphiQL de verdade continua sendo detectado")
    void graphiqlRealViraAchado() {
        assertNotNull(playground("""
                <!DOCTYPE html><html><head>
                  <link rel="stylesheet" href="//unpkg.com/graphiql/graphiql.min.css">
                </head><body>
                  <div id="graphiql">Loading...</div>
                  <script src="//unpkg.com/graphiql/graphiql.min.js"></script>
                </body></html>
                """), "assets do GraphiQL e o nó de montagem provam a UI exposta");
    }

    @Test
    @DisplayName("resposta JSON não é playground — é a API respondendo")
    void jsonNaoEPlayground() {
        assertNull(new GraphQlIntrospectionService(catalogo())
                .playgroundMarker("{\"data\":{\"__schema\":{}}}", "application/json"));
    }

    // ── Idioma da evidência ──────────────────────────────────────────────────

    @Test
    @DisplayName("a evidência segue o idioma do laudo — saía chumbada em português")
    void evidenciaSegueOIdioma() {
        try {
            LocaleContextHolder.setLocale(Locale.ENGLISH);
            assertEquals("Swagger UI assets loaded", swagger("<html><link href='swagger-ui.css'></html>"));

            LocaleContextHolder.setLocale(Locale.forLanguageTag("pt-BR"));
            assertEquals("Assets do Swagger UI carregados", swagger("<html><link href='swagger-ui.css'></html>"));
        } finally {
            LocaleContextHolder.resetLocaleContext();
        }
    }

    // ── CRLF ─────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("eco do caminho no corpo não é CRLF injection — era HIGH e descontava 12")
    void ecoNoCorpoNaoECrlf() throws IOException {
        // Página de erro que devolve o caminho pedido dentro do HTML. É o que
        // incontáveis servidores fazem, e o CRLF ali é TEXTO — não foi interpretado.
        String base = sobeServidor(t ->
                "<html><body><h1>404</h1><p>Não encontramos "
                        + t.getRequestURI().getPath() + "</p></body></html>");

        assertTrue(new CrlfService(catalogo()).scan(base).isEmpty(),
                "input ecoado no corpo não parte resposta nenhuma");
    }

    @Test
    @DisplayName("resposta partida no corpo continua valendo — é a evidência de verdade")
    void respostaPartidaNoCorpoViraAchado() throws IOException {
        // Quando o split ocorre, o cliente passa a ler a resposta injetada como corpo:
        // vem uma linha de status HTTP crua junto do probe. Página nenhuma serve isso.
        String base = sobeServidor(t ->
                "HTTP/1.1 200 OK\r\nX-CyberAudit-Test: crlf-probe-7x3k\r\n\r\n<html>injetado</html>");

        var achados = new CrlfService(catalogo()).scan(base);

        assertEquals(1, achados.size());
        assertEquals("HIGH", achados.get(0).getSeverity());
        assertTrue(achados.get(0).getInjectionType().endsWith("_SPLIT"),
                "veio: " + achados.get(0).getInjectionType());
    }
}
