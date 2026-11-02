package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.HttpFetchResult;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.aop.framework.AopProxyUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.util.ClassUtils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * O scanner fala HTTP/1.1 com o alvo (BUG-03).
 *
 * O {@code HttpClient} do JDK sai em HTTP/2 por padrão, e num alvo {@code http://} isso
 * vira um pedido de upgrade h2c na primeira requisição ({@code Connection: Upgrade,
 * HTTP2-Settings}). O Juice Shop (Node com socket.io) derruba a conexão sem responder
 * nada a esse pedido: o fetch principal voltava "HTTP/1.1 header parser received no
 * bytes", {@code httpStatus 0}, e todo módulo — inclusive os probes de XSS e SQLi —
 * rodava sem resposta para analisar. Contra o mesmo servidor, em HTTP/1.1, 200.
 *
 * Dois testes: o fetch principal ponta a ponta contra um servidor local que faz o mesmo
 * que o Juice Shop, e uma varredura dos beans provando que nenhum cliente que fala com o
 * alvo ficou em HTTP/2 — são 22 clientes em 21 módulos, e o fetch principal sozinho não
 * diz nada sobre os outros 21.
 */
@SpringBootTest
@ActiveProfiles("test")
class ScannerHttpVersionTest {

    /**
     * Clientes de APIs fixas, em HTTPS, que nunca recebem a URL do alvo: lá o h2 vem por
     * ALPN, sem upgrade, e mudar o protocolo do pagamento ou do e-mail não corrige nada.
     */
    private static final Set<Class<?>> APIS_EXTERNAS = Set.of(
            CVECorrelationService.class, CrtShService.class,
            MercadoPagoService.class, ResendEmailSender.class);

    @Autowired private ApplicationContext context;
    @Autowired private HttpFetchService httpFetchService;

    private ServidorQueDerrubaUpgrade servidor;

    @BeforeEach
    void sobeServidor() throws IOException {
        servidor = new ServidorQueDerrubaUpgrade();
        // Mesmo mecanismo do ambiente Docker do QA, que libera juice-shop e wiremock:
        // sem isto o SsrfGuard recusa 127.0.0.1 e o teste passaria sem conectar.
        SsrfGuard.setTestAllowlist(Set.of("127.0.0.1"));
    }

    @AfterEach
    void derruba() throws IOException {
        SsrfGuard.setTestAllowlist(Set.of());
        servidor.close();
    }

    @Test
    void fetchPrincipalLeAlvoQueDerrubaUpgradeH2c() {
        HttpFetchResult resultado = httpFetchService.fetchHeaders(
                servidor.url() + "/rest/products/search?q=apple");

        assertNull(resultado.getError(), "o fetch não pode falhar na conexão");
        assertEquals(200, resultado.getStatusCode());
        assertEquals(0, servidor.upgradesDerrubados.get(),
                "nenhuma requisição pode pedir upgrade para h2c");
        assertEquals(1, servidor.respondidas.get());
    }

    @Test
    void todoClienteQueFalaComOAlvoUsaHttp11() throws IllegalAccessException {
        List<String> emHttp2 = new ArrayList<>();
        int verificados = 0;

        for (Object bean : context.getBeansWithAnnotation(Component.class).values()) {
            Object alvo = AopProxyUtils.getSingletonTarget(bean);
            if (alvo == null) alvo = bean;
            Class<?> tipo = ClassUtils.getUserClass(alvo);
            if (!tipo.getPackageName().startsWith("com.joao.cyberaudit")
                    || APIS_EXTERNAS.contains(tipo)) continue;

            for (Class<?> c = tipo; c != Object.class; c = c.getSuperclass()) {
                for (Field campo : c.getDeclaredFields()) {
                    if (campo.getType() != HttpClient.class) continue;
                    campo.setAccessible(true);
                    HttpClient cliente = (HttpClient) campo.get(alvo);
                    if (cliente == null) continue;
                    verificados++;
                    if (cliente.version() != HttpClient.Version.HTTP_1_1) {
                        emHttp2.add(tipo.getSimpleName() + "." + campo.getName());
                    }
                }
            }
        }

        assertTrue(emHttp2.isEmpty(), "clientes ainda em HTTP/2: " + emHttp2);
        // Hoje são 22. O piso só impede que o teste passe vazio se a varredura deixar
        // de enxergar os beans (proxy, pacote): sem clientes, a lista acima fica vazia.
        assertTrue(verificados >= 20, "a varredura achou só " + verificados + " clientes");
    }

    /**
     * HTTP/1.1 mínimo que trata pedido de upgrade como o engine.io do socket.io: fecha a
     * conexão sem mandar nenhum byte. Sem upgrade, responde 200 com um corpo curto.
     */
    private static final class ServidorQueDerrubaUpgrade implements AutoCloseable {

        final AtomicInteger upgradesDerrubados = new AtomicInteger();
        final AtomicInteger respondidas        = new AtomicInteger();
        private final ServerSocket socket;

        ServidorQueDerrubaUpgrade() throws IOException {
            socket = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
            Thread t = new Thread(this::atende, "servidor-derruba-upgrade");
            t.setDaemon(true);
            t.start();
        }

        String url() {
            return "http://127.0.0.1:" + socket.getLocalPort();
        }

        private void atende() {
            while (!socket.isClosed()) {
                try (Socket conexao = socket.accept()) {
                    conexao.setSoTimeout(2000);
                    BufferedReader entrada = new BufferedReader(new InputStreamReader(
                            conexao.getInputStream(), StandardCharsets.ISO_8859_1));
                    boolean pedeUpgrade = false;
                    for (String linha = entrada.readLine(); linha != null && !linha.isEmpty();
                         linha = entrada.readLine()) {
                        if (linha.toLowerCase(Locale.ROOT).startsWith("upgrade:")) pedeUpgrade = true;
                    }
                    if (pedeUpgrade) {
                        upgradesDerrubados.incrementAndGet();
                        continue;   // o try-with-resources fecha sem responder
                    }
                    byte[] corpo = "<html><body>ok</body></html>".getBytes(StandardCharsets.UTF_8);
                    OutputStream saida = conexao.getOutputStream();
                    saida.write(("HTTP/1.1 200 OK\r\n"
                            + "Content-Type: text/html; charset=utf-8\r\n"
                            + "Content-Length: " + corpo.length + "\r\n"
                            + "Connection: close\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
                    saida.write(corpo);
                    saida.flush();
                    respondidas.incrementAndGet();
                } catch (IOException e) {
                    // socket fechado no close() ou cliente que desistiu: segue o laço
                }
            }
        }

        @Override
        public void close() throws IOException {
            socket.close();
        }
    }
}
