package com.joao.cyberaudit.service;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * O probe de vazamento de erro de SQL reconhece o SQLite (BUG-06).
 *
 * O probe anexa {@code '} ao 1º parâmetro e procura mensagem de erro de banco na
 * resposta. Contra o Juice Shop, {@code ?q=apple'} volta 500 com
 * {@code SQLITE_ERROR: near "'%'": syntax error} na página, e o scan dizia que não havia
 * vazamento: a lista só tinha a exceção do SQLite do Python. O SQLite é o mesmo banco em
 * toda linguagem, mas cada driver mostra o erro com outro nome — por isso um caso por
 * driver, com a mensagem como cada um a imprime.
 *
 * O servidor local imita o alvo: responde o erro só quando o valor TERMINA em {@code '}.
 * {@code '} sozinho não quebra a consulta do Juice Shop (o SQLite lê
 * {@code '%'%' ... '%'%'} como uma conta válida); é anexando ao valor original que vem o
 * erro, e é isso que o probe faz.
 */
class ErrorDisclosureServiceTest {

    private final ErrorDisclosureService service = new ErrorDisclosureService();

    private HttpServer server;
    private volatile String corpoDoErro;
    private volatile String ultimoValor;

    @BeforeEach
    void sobeServidor() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", troca -> {
            String query = troca.getRequestURI().getRawQuery();
            String valor = query == null ? "" : URLDecoder.decode(
                    query.substring(query.indexOf('=') + 1), StandardCharsets.UTF_8);
            ultimoValor = valor;
            boolean quebra = valor.endsWith("'") && corpoDoErro != null;
            byte[] corpo = (quebra ? corpoDoErro : "{\"status\":\"success\",\"data\":[]}")
                    .getBytes(StandardCharsets.UTF_8);
            troca.getResponseHeaders().add("Content-Type",
                    quebra ? "text/html; charset=utf-8" : "application/json; charset=utf-8");
            troca.sendResponseHeaders(quebra ? 500 : 200, corpo.length);
            troca.getResponseBody().write(corpo);
            troca.close();
        });
        server.start();
        // Mesmo mecanismo do ambiente Docker do QA, que libera juice-shop e wiremock:
        // sem isto o SsrfGuard recusa 127.0.0.1 e o probe daria false sem conectar.
        SsrfGuard.setTestAllowlist(Set.of("127.0.0.1"));
    }

    @AfterEach
    void derruba() {
        SsrfGuard.setTestAllowlist(Set.of());
        server.stop(0);
    }

    private String alvo() {
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/rest/products/search?q=apple";
    }

    @ParameterizedTest(name = "SQLite reconhecido: {0}")
    @ValueSource(strings = {
            // Node, driver sqlite3 — o Juice Shop, com o HTML escapado pela página de erro do Express
            "<html><head><title>Error: SQLITE_ERROR: near &quot;&#39;%&#39;&quot;: syntax error</title></head></html>",
            // Node, better-sqlite3
            "SqliteError: near \"'\": syntax error\n    at Database.prepare",
            // Java, sqlite-jdbc (xerial)
            "org.sqlite.SQLiteException: [SQLITE_ERROR] SQL error or missing database (near \"'\": syntax error)",
            // .NET, Microsoft.Data.Sqlite
            "Microsoft.Data.Sqlite.SqliteException (0x80004005): SQLite Error 1: 'near \"'\": syntax error'.",
            // Ruby (ActiveRecord)
            "ActiveRecord::StatementInvalid: SQLite3::SQLException: near \"'\": syntax error",
            // PHP, classe SQLite3
            "Warning: SQLite3::query(): Unable to prepare statement: 1, near \"'\": syntax error in /var/www/busca.php"
    })
    void reconheceErroDoSqlite(String erro) {
        corpoDoErro = erro;

        assertTrue(service.detectsDbErrorLeakage(alvo()));
        assertEquals("apple'", ultimoValor, "o probe anexa a aspa ao valor original");
    }

    /** Controle: o SQLite do Python já era reconhecido antes do BUG-06. */
    @Test
    void reconheceSqliteDoPython() {
        corpoDoErro = "sqlite3.OperationalError: near \"'\": syntax error";

        assertTrue(service.detectsDbErrorLeakage(alvo()));
    }

    /** A aspa não quebra nada: resposta normal, sem erro de banco → sem achado. */
    @Test
    void semErroDeBancoNaoAcusa() {
        corpoDoErro = null;

        assertFalse(service.detectsDbErrorLeakage(alvo()));
        assertEquals("apple'", ultimoValor, "a requisição mutada chegou ao alvo");
    }
}
