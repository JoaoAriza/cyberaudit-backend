package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.DnsSecurityResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

/**
 * Confronto entre o emissor do certificado e o CAA do domínio.
 *
 * O bug que motivou estes testes tinha duas metades. A primeira: só o primeiro
 * registro CAA era guardado, então um domínio com seis CAs autorizadas era
 * auditado contra uma. A segunda: a comparação era textual, e nem
 * "Let's Encrypt" ↔ letsencrypt.org (apóstrofo) nem "Google Trust Services" ↔
 * pki.goog (nomes sem relação) casavam. Juntas, faziam o scanner acusar
 * emissão indevida de certificado em domínios perfeitamente configurados —
 * o alarme mais grave que o produto sabe dar, disparado contra um alvo limpo.
 */
class CertTransparencyCaaTest {

    private final CertTransparencyService service =
            new CertTransparencyService(mock(CrtShService.class));

    @SuppressWarnings("unchecked")
    private List<String> inesperados(Set<String> emissores, DnsSecurityResult dns) {
        return (List<String>) ReflectionTestUtils.invokeMethod(
                service, "detectUnexpectedIssuers", emissores, dns);
    }

    private String caa(String tag, String valor) {
        return "exemplo.com.\t300\tIN\tCAA\t0 " + tag + " \"" + valor + "\"";
    }

    /** CAA real do cyberauditapp.com: comodoca.com é o primeiro da lista. */
    private DnsSecurityResult caaCompleto() {
        return DnsSecurityResult.builder()
                .caaPresent(true)
                .caaRecord(caa("issue", "comodoca.com"))
                .caaRecords(List.of(
                        caa("issue", "comodoca.com"),
                        caa("issue", "digicert.com; cansignhttpexchanges=yes"),
                        caa("issue", "letsencrypt.org"),
                        caa("issue", "pki.goog; cansignhttpexchanges=yes"),
                        caa("issue", "sectigo.com"),
                        caa("issue", "ssl.com"),
                        caa("issuewild", "letsencrypt.org")))
                .build();
    }

    @Test
    @DisplayName("emissores autorizados não viram alerta, mesmo fora do primeiro registro")
    void emissoresLegitimosNaoSaoAcusados() {
        List<String> r = inesperados(
                Set.of("let's encrypt", "google trust services"), caaCompleto());

        assertTrue(r.isEmpty(),
                "Let's Encrypt e Google Trust Services estão no CAA — acusar é falso positivo, veio: " + r);
    }

    @Test
    @DisplayName("emissor fora do CAA continua sendo reportado")
    void emissorForaDoCaaEhReportado() {
        List<String> r = inesperados(
                Set.of("let's encrypt", "shady certs ltda"), caaCompleto());

        assertEquals(List.of("shady certs ltda"), r,
                "o alerta precisa continuar valendo para quem realmente não está autorizado");
    }

    @Test
    @DisplayName("parâmetros depois do ; não entram no nome do domínio")
    void parametrosDaTagSaoIgnorados() {
        DnsSecurityResult dns = DnsSecurityResult.builder()
                .caaPresent(true)
                .caaRecords(List.of(caa("issue", "digicert.com; cansignhttpexchanges=yes")))
                .build();

        assertTrue(inesperados(Set.of("digicert"), dns).isEmpty(),
                "cansignhttpexchanges é parâmetro, o domínio autorizado é digicert.com");
    }

    @Test
    @DisplayName("scan antigo sem caaRecords ainda usa o registro singular")
    void compatibilidadeComScanAntigo() {
        DnsSecurityResult dns = DnsSecurityResult.builder()
                .caaPresent(true)
                .caaRecord(caa("issue", "letsencrypt.org"))
                .build();

        assertTrue(inesperados(Set.of("let's encrypt"), dns).isEmpty(),
                "resultados gravados antes do campo novo não podem virar alerta");
    }

    @Test
    @DisplayName("CAA só com iodef não autoriza ninguém, mas também não acusa")
    void caaSemTagIssueNaoAcusa() {
        DnsSecurityResult dns = DnsSecurityResult.builder()
                .caaPresent(true)
                .caaRecords(List.of("exemplo.com.\t300\tIN\tCAA\t0 iodef \"mailto:sec@exemplo.com\""))
                .build();

        assertTrue(inesperados(Set.of("let's encrypt"), dns).isEmpty(),
                "sem nenhuma tag issue não há base para afirmar que o emissor é indevido");
    }

    @Test
    @DisplayName("emissor desconhecido não gera alerta")
    void emissorDesconhecidoEhIgnorado() {
        assertTrue(inesperados(Set.of("Unknown", "unknown", ""), caaCompleto()).isEmpty(),
                "não saber quem emitiu não é o mesmo que saber que foi alguém indevido");
    }

    @Test
    @DisplayName("sem CAA no domínio não há o que confrontar")
    void semCaaNaoAcusa() {
        DnsSecurityResult dns = DnsSecurityResult.builder().caaPresent(false).build();

        assertTrue(inesperados(Set.of("shady certs ltda"), dns).isEmpty(),
                "sem CAA qualquer CA pública pode emitir — não há violação a reportar");
    }
}
