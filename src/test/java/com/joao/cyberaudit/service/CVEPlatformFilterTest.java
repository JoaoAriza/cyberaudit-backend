package com.joao.cyberaudit.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.joao.cyberaudit.model.TechFingerprintResult;
import com.joao.cyberaudit.service.CVECorrelationService.Plataforma;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * O filtro de plataforma que descarta CVE de SO que o alvo não é.
 *
 * Motivado por um falso positivo real: o {@code www.lojadivinanoite.com.br} (Apache
 * + PHP 7.4.33 na Locaweb, Linux) veio com o CVE-2024-3566 (CVSS 9.8, CRITICAL) —
 * command injection via {@code CreateProcess} do Windows. A config do CVE no NVD traz
 * {@code cpe:2.3:o:microsoft:windows}, dizendo que só vale rodando em Windows. Casar
 * pela versão do PHP sem olhar o SO transformava uma vulnerabilidade do Windows num
 * "crítico" de −10 no score de um site Linux.
 *
 * Fixtures montadas na forma do NVD 2.0 real: os CPEs de aplicação num nó, e o CPE de
 * SO ({@code part = o}) num AND à parte — que é como o NVD expressa "rodando em".
 */
class CVEPlatformFilterTest {

    private final CVECorrelationService service = new CVECorrelationService();
    private final ObjectMapper jackson = new ObjectMapper();

    private JsonNode cve(String configuracoesJson) {
        try {
            return jackson.readTree("{\"id\":\"CVE-TESTE\",\"configurations\":"
                    + configuracoesJson + "}");
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    /** Config no formato do CVE-2024-3566: runtimes num OR, Windows num AND ("rodando em"). */
    private static final String CONFIG_WINDOWS_ONLY = """
        [{"nodes":[{"operator":"OR","cpeMatch":[
            {"vulnerable":true,"criteria":"cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"},
            {"vulnerable":true,"criteria":"cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*"}]}]},
         {"nodes":[{"operator":"OR","cpeMatch":[
            {"vulnerable":false,"criteria":"cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"}]}]}]""";

    /** Config sem CPE de SO: um CVE comum de PHP, aplica em qualquer plataforma. */
    private static final String CONFIG_SEM_SO = """
        [{"nodes":[{"operator":"OR","cpeMatch":[
            {"vulnerable":true,"criteria":"cpe:2.3:a:php:php:7.4.33:*:*:*:*:*:*:*"}]}]}]""";

    /** Config presa a Linux: CVE de kernel/servidor que só existe em Unix. */
    private static final String CONFIG_LINUX_ONLY = """
        [{"nodes":[{"operator":"AND","cpeMatch":[
            {"vulnerable":true,"criteria":"cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"},
            {"vulnerable":false,"criteria":"cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"}]}]}]""";

    /** Multiplataforma: Windows E Linux listados — não é exclusivo de ninguém. */
    private static final String CONFIG_MULTIPLATAFORMA = """
        [{"nodes":[{"operator":"OR","cpeMatch":[
            {"vulnerable":false,"criteria":"cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"},
            {"vulnerable":false,"criteria":"cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"}]}]}]""";

    // ── Leitura do SO exigido pelo CVE ───────────────────────────────────────

    @Test
    @DisplayName("CPE o:microsoft:windows exige Windows")
    void windowsOnly() {
        assertEquals(Plataforma.WINDOWS, service.soExigidoPeloCve(cve(CONFIG_WINDOWS_ONLY)));
    }

    @Test
    @DisplayName("CPE o:linux exige não-Windows")
    void linuxOnly() {
        assertEquals(Plataforma.UNIX, service.soExigidoPeloCve(cve(CONFIG_LINUX_ONLY)));
    }

    @Test
    @DisplayName("sem CPE de SO na config, o CVE não tem restrição de plataforma")
    void semSo() {
        assertEquals(Plataforma.DESCONHECIDA, service.soExigidoPeloCve(cve(CONFIG_SEM_SO)));
    }

    @Test
    @DisplayName("Windows E Linux juntos = multiplataforma, sem exclusividade")
    void multiplataforma() {
        assertEquals(Plataforma.DESCONHECIDA, service.soExigidoPeloCve(cve(CONFIG_MULTIPLATAFORMA)));
    }

    // ── Inferência do SO do alvo ─────────────────────────────────────────────

    @Test
    @DisplayName("Apache/PHP sem pista de SO fica DESCONHECIDA")
    void alvoSemPista() {
        TechFingerprintResult fp = TechFingerprintResult.builder()
                .webServer("Apache HTTP Server").language("PHP").build();
        assertEquals(Plataforma.DESCONHECIDA, service.plataformaDoAlvo(fp));
    }

    @Test
    @DisplayName("\"(Ubuntu)\" no Server (via evidence) marca Unix")
    void alvoUnixPeloServer() {
        TechFingerprintResult fp = TechFingerprintResult.builder()
                .webServer("Apache HTTP Server")
                .evidence(List.of("Server: Apache/2.4.41 (Ubuntu)"))
                .build();
        assertEquals(Plataforma.UNIX, service.plataformaDoAlvo(fp));
    }

    @Test
    @DisplayName("IIS marca Windows")
    void alvoWindowsPorIis() {
        TechFingerprintResult fp = TechFingerprintResult.builder()
                .webServer("Microsoft IIS").build();
        assertEquals(Plataforma.WINDOWS, service.plataformaDoAlvo(fp));
    }

    // ── A decisão de aplicar ─────────────────────────────────────────────────

    @Test
    @DisplayName("CVE Windows-only cai em alvo Unix e em alvo desconhecido")
    void windowsOnlyNaoSeAplicaForaDoWindows() {
        assertFalse(service.cveSeAplica(Plataforma.WINDOWS, Plataforma.UNIX));
        assertFalse(service.cveSeAplica(Plataforma.WINDOWS, Plataforma.DESCONHECIDA));
        assertTrue(service.cveSeAplica(Plataforma.WINDOWS, Plataforma.WINDOWS));
    }

    @Test
    @DisplayName("CVE não-Windows só cai quando o alvo é comprovadamente Windows")
    void naoWindowsSoCaiEmWindows() {
        assertFalse(service.cveSeAplica(Plataforma.UNIX, Plataforma.WINDOWS));
        assertTrue(service.cveSeAplica(Plataforma.UNIX, Plataforma.UNIX));
        // Unix é o caso comum e costuma vir sem marcador: desconhecido não descarta.
        assertTrue(service.cveSeAplica(Plataforma.UNIX, Plataforma.DESCONHECIDA));
    }

    @Test
    @DisplayName("CVE sem restrição de SO aplica em qualquer alvo")
    void semRestricaoAplicaSempre() {
        for (Plataforma alvo : Plataforma.values()) {
            assertTrue(service.cveSeAplica(Plataforma.DESCONHECIDA, alvo), "alvo " + alvo);
        }
    }

    // ── O caso real, ponta a ponta ───────────────────────────────────────────

    @Test
    @DisplayName("o CVE-2024-3566 (Windows) é descartado no Apache/PHP do lojadivinanoite")
    void casoRealLojadivinanoite() {
        // Fingerprint como o do laudo: Apache + PHP, sem marcador de SO → DESCONHECIDA.
        Plataforma alvo = service.plataformaDoAlvo(TechFingerprintResult.builder()
                .webServer("Apache HTTP Server").language("PHP").build());

        Plataforma exigido = service.soExigidoPeloCve(cve(CONFIG_WINDOWS_ONLY));

        assertFalse(service.cveSeAplica(exigido, alvo),
                "CVE de CreateProcess do Windows não pode contar num Apache/PHP Linux");
    }

    @Test
    @DisplayName("o mesmo CVE seria mantido se o alvo fosse mesmo Windows")
    void mesmoCveFicaEmWindows() {
        Plataforma alvo = service.plataformaDoAlvo(TechFingerprintResult.builder()
                .webServer("Microsoft IIS").framework("ASP.NET").build());

        assertTrue(service.cveSeAplica(service.soExigidoPeloCve(cve(CONFIG_WINDOWS_ONLY)), alvo),
                "num alvo Windows o CVE volta a valer — o filtro não é um mudo geral");
    }
}
