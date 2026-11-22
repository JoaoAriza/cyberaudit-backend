package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.HttpFetchResult;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLHandshakeException;
import java.io.IOException;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpTimeoutException;
import java.nio.channels.UnresolvedAddressException;
import java.nio.charset.StandardCharsets;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * O fetch principal distingue "nada aceitou a conexão" de "conectou e deu erro".
 *
 * Parte da regressão do BUG-16 (cyberaudit-qa). O orchestrator recusa o alvo
 * ({@code TARGET_UNREACHABLE}) só quando {@code semConexao} vale em http e em https. Um
 * site que conecta e falha depois (TLS quebrado, servidor lento) tem o que auditar e segue
 * escaneado como antes. E o erro dizia "Erro ao conectar: null": a falha de conexão do
 * HttpClient vem sem mensagem.
 *
 * Tudo em 127.0.0.1, menos o domínio {@code .invalid}, que nunca resolve (RFC 6761). O
 * fetch passa cada salto pelo SsrfGuard, então 127.0.0.1 fica liberado só durante a classe.
 */
class HttpFetchSemConexaoTest {

    private final HttpFetchService service = new HttpFetchService(new FormSurfaceService());
    private HttpServer servidor;
    private ServerSocket semTls;

    @BeforeEach
    void liberaLoopback() {
        SsrfGuard.setTestAllowlist(Set.of("127.0.0.1"));
    }

    @AfterEach
    void derruba() throws IOException {
        SsrfGuard.setTestAllowlist(Set.of());
        if (servidor != null) servidor.stop(0);
        if (semTls != null) semTls.close();
    }

    private static int portaFechada() throws IOException {
        try (ServerSocket socket = new ServerSocket()) {
            socket.bind(new InetSocketAddress("127.0.0.1", 0));
            return socket.getLocalPort();
        }
    }

    /** Servidor http comum em 127.0.0.1; devolve {@code host:porta}. */
    private String servidorHttp() throws IOException {
        servidor = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        servidor.createContext("/", troca -> {
            byte[] corpo = "<html><body>ok</body></html>".getBytes(StandardCharsets.UTF_8);
            troca.sendResponseHeaders(200, corpo.length);
            troca.getResponseBody().write(corpo);
            troca.close();
        });
        servidor.start();
        return "127.0.0.1:" + servidor.getAddress().getPort();
    }

    /**
     * Aceita a conexão e responde em texto puro, sem TLS. O handshake falha na hora;
     * com um servidor http de verdade o cliente ficaria esperando até o timeout.
     */
    private String servidorQueNaoFalaTls() throws IOException {
        semTls = new ServerSocket();
        semTls.bind(new InetSocketAddress("127.0.0.1", 0));
        Thread atende = new Thread(() -> {
            while (!semTls.isClosed()) {
                try (Socket conexao = semTls.accept()) {
                    OutputStream saida = conexao.getOutputStream();
                    saida.write("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
                            .getBytes(StandardCharsets.US_ASCII));
                    saida.flush();
                } catch (IOException fechou) {
                    return;
                }
            }
        });
        atende.setDaemon(true);
        atende.start();
        return "127.0.0.1:" + semTls.getLocalPort();
    }

    // ── O fetch de verdade ──────────────────────────────────────────────────

    @Test
    @DisplayName("porta fechada: semConexao, e o erro diz 'conexão recusada' em vez de 'null'")
    void portaFechadaESemConexao() throws IOException {
        HttpFetchResult r = service.fetchHeaders("http://127.0.0.1:" + portaFechada() + "/");

        assertTrue(r.isSemConexao());
        assertEquals("Erro ao conectar: conexão recusada", r.getError());
    }

    @Test
    @DisplayName("domínio que não resolve: semConexao, com o motivo do DNS")
    void naoResolve() {
        HttpFetchResult r = service.fetchHeaders("http://nao-existe-qa.invalid/");

        assertTrue(r.isSemConexao());
        assertEquals("Erro ao conectar: o domínio não resolve no DNS", r.getError());
    }

    @Test
    @DisplayName("https num servidor sem TLS: a conexão abriu, então não é semConexao")
    void tlsQuebradoNaoESemConexao() throws IOException {
        HttpFetchResult r = service.fetchHeaders("https://" + servidorQueNaoFalaTls() + "/");

        assertNotNull(r.getError(), "o handshake contra um servidor sem TLS tem de falhar");
        assertFalse(r.isSemConexao(), "quem falhou foi o TLS, não a conexão: " + r.getError());
        assertFalse(r.getError().contains("null"), r.getError());
    }

    @Test
    @DisplayName("controle: servidor que responde não tem erro nem semConexao")
    void respondeu() throws IOException {
        HttpFetchResult r = service.fetchHeaders("http://" + servidorHttp() + "/");

        assertNull(r.getError());
        assertFalse(r.isSemConexao());
        assertEquals(200, r.getStatusCode());
    }

    // ── A classificação da causa ────────────────────────────────────────────

    @Test
    @DisplayName("semConexao acha a falha de conexão embrulhada noutra exceção")
    void semConexaoNaCadeia() {
        assertTrue(HttpFetchService.semConexao(new IOException("embrulho", new ConnectException())));
        assertTrue(HttpFetchService.semConexao(new IOException(new UnknownHostException("x.invalid"))));
        assertTrue(HttpFetchService.semConexao(new HttpConnectTimeoutException("connect timed out")));
    }

    @Test
    @DisplayName("conectou e falhou depois (timeout de resposta, TLS) não é semConexao")
    void conectouNaoESemConexao() {
        assertFalse(HttpFetchService.semConexao(new HttpTimeoutException("request timed out")));
        assertFalse(HttpFetchService.semConexao(new SSLHandshakeException("bad record")));
    }

    @Test
    @DisplayName("o motivo nunca sai 'null'")
    void motivoNuncaNull() {
        assertEquals("conexão recusada", HttpFetchService.motivo(new ConnectException()));
        // HttpConnectTimeoutException é subclasse de HttpTimeoutException: a ordem importa.
        assertEquals("a conexão não abriu a tempo",
                HttpFetchService.motivo(new HttpConnectTimeoutException("connect timed out")));
        assertEquals("o servidor aceitou a conexão, mas não respondeu a tempo",
                HttpFetchService.motivo(new HttpTimeoutException("request timed out")));
        assertEquals("IOException", HttpFetchService.motivo(new IOException()));
    }

    @Test
    @DisplayName("DNS embrulhado em ConnectException, como o HttpClient faz, é DNS e não 'recusada'")
    void dnsDentroDeConnectException() {
        ConnectException comoOHttpClientLanca = new ConnectException();
        comoOHttpClientLanca.initCause(new UnresolvedAddressException());

        assertEquals("o domínio não resolve no DNS", HttpFetchService.motivo(comoOHttpClientLanca));
        assertTrue(HttpFetchService.semConexao(comoOHttpClientLanca));
    }
}
