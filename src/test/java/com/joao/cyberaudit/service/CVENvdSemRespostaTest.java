package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.CVEFinding;
import com.joao.cyberaudit.model.TechFingerprintResult;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * "O NVD não respondeu" deixou de ser igual a "sem CVE".
 *
 * Parte da regressão do BUG-16 (cyberaudit-qa). A falha da consulta (5xx, timeout, 429
 * depois da segunda tentativa) virava lista vazia, e o módulo CVE marcava "OK": o laudo
 * dizia que o PHP detectado não tinha CVE quando ninguém tinha conferido. Agora a
 * correlação diz se ficou {@code completa}, e o orchestrator marca o módulo "ERROR"
 * quando não ficou (decisão do dono, 2026-11-22).
 *
 * O NVD é um servidor local que responde, por produto, o status que cada teste pede.
 */
class CVENvdSemRespostaTest {

    /** CVE do próprio PHP, na forma do NVD 2.0. */
    private static final String CVE_PHP = """
        {"cve":{"id":"CVE-2007-3205","published":"2007-06-11T17:30:00.000",
         "descriptions":[{"lang":"en","value":"The parse_str function in PHP, when called without a second parameter, might allow remote attackers to overwrite arbitrary variables."}],
         "metrics":{"cvssMetricV2":[{"cvssData":{"baseScore":5.0},"baseSeverity":"MEDIUM"}]},
         "configurations":[{"nodes":[{"operator":"OR","negate":false,"cpeMatch":[
             {"vulnerable":true,"criteria":"cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"}]}]}]}}""";

    private HttpServer server;
    private CVECorrelationService service;
    private volatile int statusPhp   = 200;
    private volatile int statusNginx = 200;

    @BeforeEach
    void sobeNvdLocal() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/rest/json/cves/2.0", troca -> {
            String query = URLDecoder.decode(troca.getRequestURI().getRawQuery(), StandardCharsets.UTF_8);
            boolean php = query.contains(":php:php:");
            int status = php ? statusPhp : statusNginx;
            String corpo = status != 200 ? "{\"message\":\"indisponível\"}"
                    : php ? resposta(CVE_PHP) : resposta();
            byte[] bytes = corpo.getBytes(StandardCharsets.UTF_8);
            troca.getResponseHeaders().set("Content-Type", "application/json");
            troca.sendResponseHeaders(status, bytes.length);
            troca.getResponseBody().write(bytes);
            troca.close();
        });
        server.start();
        service = new CVECorrelationService(
                "http://127.0.0.1:" + server.getAddress().getPort() + "/rest/json/cves/2.0");
    }

    @AfterEach
    void derrubaNvdLocal() {
        server.stop(0);
    }

    private static String resposta(String... vulnerabilidades) {
        return "{\"resultsPerPage\":" + vulnerabilidades.length + ",\"startIndex\":0,"
                + "\"totalResults\":" + vulnerabilidades.length + ",\"format\":\"NVD_CVE\","
                + "\"version\":\"2.0\",\"vulnerabilities\":["
                + String.join(",", vulnerabilidades) + "]}";
    }

    private static TechFingerprintResult detectou(Map<String, String> versoes) {
        return TechFingerprintResult.builder().detectedVersions(versoes).build();
    }

    private static List<String> ids(CVECorrelationService.Correlacao c) {
        return c.achados().stream().map(CVEFinding::getCveId).toList();
    }

    @Test
    @DisplayName("NVD fora do ar (503): a correlação sai incompleta, não 'sem CVE'")
    void nvdForaDoArFicaIncompleta() {
        statusPhp = 503;

        CVECorrelationService.Correlacao c = service.correlacionar(detectou(Map.of("PHP", "8.3.36")));

        assertFalse(c.completa());
        assertTrue(c.achados().isEmpty());
    }

    @Test
    @DisplayName("NVD inalcançável (porta fechada): também incompleta")
    void nvdInalcancavelFicaIncompleta() throws IOException {
        int fechada;
        try (ServerSocket socket = new ServerSocket()) {
            socket.bind(new InetSocketAddress("127.0.0.1", 0));
            fechada = socket.getLocalPort();
        }
        var semNvd = new CVECorrelationService("http://127.0.0.1:" + fechada + "/rest/json/cves/2.0");

        assertFalse(semNvd.correlacionar(detectou(Map.of("PHP", "8.3.36"))).completa());
    }

    @Test
    @DisplayName("uma consulta falhou e a outra respondeu: incompleta, e o achado da que respondeu fica")
    void falhaParcialGuardaOQueVeio() {
        statusNginx = 503;
        Map<String, String> versoes = new LinkedHashMap<>();
        versoes.put("PHP", "8.3.36");
        versoes.put("nginx", "1.18.0");

        CVECorrelationService.Correlacao c = service.correlacionar(detectou(versoes));

        assertFalse(c.completa(), "o nginx ficou sem verificação");
        assertEquals(List.of("CVE-2007-3205"), ids(c));
    }

    // ── Controles: o que continua sendo resposta ────────────────────────────

    @Test
    @DisplayName("controle: NVD respondeu, a correlação sai completa e com o CVE")
    void nvdRespondeuFicaCompleta() {
        CVECorrelationService.Correlacao c = service.correlacionar(detectou(Map.of("PHP", "8.3.36")));

        assertTrue(c.completa());
        assertEquals(List.of("CVE-2007-3205"), ids(c));
    }

    @Test
    @DisplayName("controle: 404 do NVD é resposta (cpeName desconhecido), completa e sem CVE")
    void notFoundEResposta() {
        statusPhp = 404;

        CVECorrelationService.Correlacao c = service.correlacionar(detectou(Map.of("PHP", "8.3.36")));

        assertTrue(c.completa());
        assertTrue(c.achados().isEmpty());
    }

    @Test
    @DisplayName("controle: sem versão detectada não há o que consultar, completa")
    void semVersaoNaoConsulta() {
        statusPhp = 503;   // se consultasse, ficaria incompleta

        assertTrue(service.correlacionar(detectou(Map.of())).completa());
        assertTrue(service.correlacionar(null).completa());
    }

    @Test
    @DisplayName("correlate, usado fora do scan, continua devolvendo só a lista")
    void correlateDevolveSoALista() {
        statusPhp = 503;

        assertTrue(service.correlate(detectou(Map.of("PHP", "8.3.36"))).isEmpty());
    }
}
