package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.SourceMapFinding;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.ResourceBundleMessageSource;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A sonda de Actuator contra um servidor HTTP de verdade.
 *
 * O {@link ActuatorProbeTest} cobre a decisão; este cobre o CAMINHO — requisição,
 * content-type, corpo e o texto do achado. É o que reproduz de ponta a ponta o caso
 * do cliente: {@code github.com/actuator} responde HTTP 200 com HTML de perfil, e
 * era reportado como Actuator exposto.
 *
 * Sem rede: o servidor sobe em localhost numa porta efêmera e serve exatamente as
 * duas respostas que interessam.
 */
class ActuatorProbeHttpTest {

    private HttpServer server;

    private SourceMapService service() {
        var source = new ResourceBundleMessageSource();
        source.setBasename("messages");
        source.setDefaultEncoding("UTF-8");
        source.setFallbackToSystemLocale(false);
        return new SourceMapService(new MessageCatalog(source));
    }

    /** Sobe um servidor que responde `corpo` com `contentType` em /actuator. */
    private String sobeServidor(String corpo, String contentType) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", troca -> {
            byte[] bytes = corpo.getBytes(StandardCharsets.UTF_8);
            troca.getResponseHeaders().add("Content-Type", contentType);
            troca.sendResponseHeaders(200, bytes.length);
            troca.getResponseBody().write(bytes);
            troca.close();
        });
        server.start();
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterEach
    void derruba() {
        if (server != null) server.stop(0);
        LocaleContextHolder.resetLocaleContext();
    }

    private List<SourceMapFinding> actuatorFindings(String base) {
        return service().scan(base).stream()
                .filter(f -> "ACTUATOR".equals(f.getType()))
                .toList();
    }

    @Test
    @DisplayName("perfil HTML em /actuator não vira achado — o caso github.com/actuator")
    void perfilHtmlNaoViraAchado() throws IOException {
        // Recorte fiel do que o GitHub serve: HTTP 200, text/html, e um role="status"
        // — que era o marcador genérico que disparava o achado.
        String base = sobeServidor("""
                <!DOCTYPE html>
                <html lang="en"><body>
                  <div role="status" class="js-flash-container"></div>
                  <h1>actuator</h1><p>171 followers · 3 following</p>
                </body></html>
                """, "text/html; charset=utf-8");

        assertTrue(actuatorFindings(base).isEmpty(),
                "página de perfil não é Spring Boot Actuator");
    }

    @Test
    @DisplayName("Actuator de verdade continua sendo detectado, com evidência no idioma pedido")
    void actuatorRealViraAchado() throws IOException {
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        String base = sobeServidor(
                "{\"_links\":{\"self\":{\"href\":\"/actuator\",\"templated\":false}}}",
                "application/vnd.spring-boot.actuator.v3+json");

        List<SourceMapFinding> achados = actuatorFindings(base);

        assertEquals(1, achados.size(), "o índice HAL do Actuator tem de ser detectado");
        SourceMapFinding f = achados.get(0);
        assertEquals("MEDIUM", f.getSeverity());
        assertTrue(f.getEvidence().contains("root endpoint exposed"),
                "a evidência saía chumbada em português no laudo em inglês: " + f.getEvidence());
    }
}
