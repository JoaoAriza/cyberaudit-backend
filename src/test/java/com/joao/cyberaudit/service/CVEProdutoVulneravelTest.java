package com.joao.cyberaudit.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.joao.cyberaudit.model.CVEFinding;
import com.joao.cyberaudit.model.TechFingerprintResult;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CVE de extensão não vira CVE do PHP (BUG-08).
 *
 * Falso positivo real, contestado por um cliente: um site em PHP 8.3.36 veio com o
 * CVE-2013-2220, CVSS 7.5 — buffer overflow na extensão PECL radius antes da 1.2.7, que
 * nem faz parte do PHP. No NVD a config desse CVE é um AND: a extensão marcada
 * {@code vulnerable:true} e o {@code php:php} marcado {@code vulnerable:false}, que quer
 * dizer só "roda em PHP". A consulta por {@code cpeName} casa com qualquer CPE da config,
 * inclusive o de plataforma; o NVD só se limita ao lado vulnerável com o parâmetro
 * {@code isVulnerable}. Medido em 2026-11-07 para {@code cpe:2.3:a:php:php:8.3.36}: dois
 * CVEs sem o parâmetro, um com ele.
 *
 * O servidor local imita o NVD nesse ponto: sem {@code isVulnerable} devolve os dois CVEs,
 * com ele só o do próprio PHP. As fixtures têm a forma do NVD 2.0 e as configs reais dos
 * dois CVEs (a lista de versões da extensão encurtada).
 */
class CVEProdutoVulneravelTest {

    /** Extensão radius vulnerável, PHP só como plataforma ("roda em"). */
    private static final String CVE_2013_2220 = """
        {"cve":{"id":"CVE-2013-2220","published":"2013-07-31T13:20:24.000",
         "descriptions":[{"lang":"en","value":"Buffer overflow in the radius_get_vendor_attr function in the Radius extension before 1.2.7 for PHP."}],
         "metrics":{"cvssMetricV2":[{"cvssData":{"baseScore":7.5},"baseSeverity":"HIGH"}]},
         "configurations":[{"operator":"AND","nodes":[
           {"operator":"OR","negate":false,"cpeMatch":[
             {"vulnerable":true,"criteria":"cpe:2.3:a:radius_extension_project:radius:*:*:*:*:*:*:*:*","versionEndIncluding":"1.2.6"},
             {"vulnerable":true,"criteria":"cpe:2.3:a:radius_extension_project:radius:1.2.5:*:*:*:*:*:*:*"}]},
           {"operator":"OR","negate":false,"cpeMatch":[
             {"vulnerable":false,"criteria":"cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"}]}]}]}}""";

    /** CVE do próprio PHP: {@code php:php} é o vulnerável. Controle positivo. */
    private static final String CVE_2007_3205 = """
        {"cve":{"id":"CVE-2007-3205","published":"2007-06-11T17:30:00.000",
         "descriptions":[{"lang":"en","value":"The parse_str function in PHP, when called without a second parameter, might allow remote attackers to overwrite arbitrary variables."}],
         "metrics":{"cvssMetricV2":[{"cvssData":{"baseScore":5.0},"baseSeverity":"MEDIUM"}]},
         "configurations":[{"nodes":[{"operator":"OR","negate":false,"cpeMatch":[
             {"vulnerable":true,"criteria":"cpe:2.3:a:hardened-php_project:hardened-php:*:*:*:*:*:*:*:*"},
             {"vulnerable":true,"criteria":"cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"}]}]}]}}""";

    private HttpServer server;
    private CVECorrelationService service;
    private volatile String ultimaQuery = "";
    /** NVD que ignora o {@code isVulnerable}: prova que a checagem local se sustenta sozinha. */
    private volatile boolean ignoraIsVulnerable;

    @BeforeEach
    void sobeNvdLocal() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/rest/json/cves/2.0", troca -> {
            String query = troca.getRequestURI().getRawQuery();
            ultimaQuery = query == null ? "" : URLDecoder.decode(query, StandardCharsets.UTF_8);

            boolean soLadoVulneravel = !ignoraIsVulnerable && ultimaQuery.contains("isVulnerable");
            String corpo = soLadoVulneravel
                    ? resposta(CVE_2007_3205)
                    : resposta(CVE_2013_2220, CVE_2007_3205);

            byte[] bytes = corpo.getBytes(StandardCharsets.UTF_8);
            troca.getResponseHeaders().set("Content-Type", "application/json");
            troca.sendResponseHeaders(200, bytes.length);
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

    private List<String> cvesDe(String software, String versao) {
        TechFingerprintResult fp = TechFingerprintResult.builder()
                .detectedVersions(Map.of(software, versao))
                .build();
        return service.correlate(fp).stream().map(CVEFinding::getCveId).toList();
    }

    @Test
    @DisplayName("A consulta ao NVD pede só os CVEs em que o produto é o vulnerável")
    void consultaPedeIsVulnerable() {
        cvesDe("PHP", "8.3.36");

        assertTrue(ultimaQuery.contains("cpeName=cpe:2.3:a:php:php:8.3.36:"), ultimaQuery);
        assertTrue(ultimaQuery.contains("isVulnerable"), ultimaQuery);
    }

    @Test
    @DisplayName("PHP 8.3.36 não recebe o CVE da extensão radius; o CVE do próprio PHP fica")
    void extensaoNaoViraCveDoPhp() {
        assertEquals(List.of("CVE-2007-3205"), cvesDe("PHP", "8.3.36"));
    }

    @Test
    @DisplayName("Mesmo com o NVD ignorando o isVulnerable, o CVE em que o PHP é só plataforma cai")
    void checagemLocalSeSustentaSozinha() {
        ignoraIsVulnerable = true;

        assertEquals(List.of("CVE-2007-3205"), cvesDe("PHP", "8.3.36"));
    }

    // ── A checagem local, direto na config ────────────────────────────────────

    private final ObjectMapper jackson = new ObjectMapper();

    private JsonNode cve(String vulnerabilidade) {
        try {
            return jackson.readTree(vulnerabilidade).path("cve");
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    @Test
    @DisplayName("php:php com vulnerable:false é plataforma, não produto vulnerável")
    void plataformaNaoConta() {
        assertFalse(service.produtoMarcadoVulneravel(cve(CVE_2013_2220), "php", "php"));
    }

    @Test
    @DisplayName("php:php com vulnerable:true conta, mesmo ao lado de outros produtos")
    void produtoVulneravelConta() {
        assertTrue(service.produtoMarcadoVulneravel(cve(CVE_2007_3205), "php", "php"));
    }

    @Test
    @DisplayName("Produto vulnerável num AND com o SO como plataforma continua contando")
    void produtoVulneravelComSoComoPlataforma() {
        String apacheEmLinux = """
            {"cve":{"id":"CVE-TESTE","configurations":[{"operator":"AND","nodes":[
              {"operator":"OR","cpeMatch":[
                {"vulnerable":true,"criteria":"cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"}]},
              {"operator":"OR","cpeMatch":[
                {"vulnerable":false,"criteria":"cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"}]}]}]}}""";

        assertTrue(service.produtoMarcadoVulneravel(cve(apacheEmLinux), "apache", "http_server"));
        assertFalse(service.produtoMarcadoVulneravel(cve(apacheEmLinux), "apache", "tomcat"));
    }
}
