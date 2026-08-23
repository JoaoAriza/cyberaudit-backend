package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.DnsSecurityResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

/**
 * Distinção entre "registro ausente" e "não consegui consultar".
 *
 * O bug que motivou estes testes: o host bloqueia UDP/53, o dnsjava devolve null
 * em vez de erro, e o scanner concluía ausência. Resultado: TODO domínio, mesmo
 * google.com, era reportado com risco de spoofing — laudo errado com aparência
 * de laudo correto, que é o pior defeito possível num produto de auditoria.
 */
class DnsSecurityRiskTest {

    private final DnsSecurityService service =
            new DnsSecurityService(mock(PublicSuffixService.class));

    private String risco(DnsSecurityResult r) {
        return (String) ReflectionTestUtils.invokeMethod(service, "calculateRisk", r);
    }

    private String resumo(DnsSecurityResult r) {
        return (String) ReflectionTestUtils.invokeMethod(service, "buildSummary", r);
    }

    @Test
    @DisplayName("consulta que falhou vira UNKNOWN, não risco de spoofing")
    void consultaFalhaNaoViraAchado() {
        DnsSecurityResult r = DnsSecurityResult.builder()
                .lookupFailed(true)
                .spfPresent(false)
                .dmarcPresent(false)
                .mxPresent(false)
                .build();

        assertEquals("UNKNOWN", risco(r),
                "sem conseguir consultar, afirmar ausência é inventar resultado");
    }

    @Test
    @DisplayName("UNKNOWN se explica como inconclusivo, não como achado")
    void resumoDeUnknownEHonesto() {
        DnsSecurityResult r = DnsSecurityResult.builder().lookupFailed(true).build();
        r.setEmailSpoofingRisk(risco(r));

        String texto = resumo(r);
        assertTrue(texto.toLowerCase().contains("inconclusivo"),
                "o texto precisa deixar claro que não é um achado: " + texto);
    }

    @Test
    @DisplayName("consulta bem-sucedida e sem registros continua sendo achado real")
    void ausenciaRealContinuaPenalizando() {
        DnsSecurityResult r = DnsSecurityResult.builder()
                .lookupFailed(false)
                .spfPresent(false)
                .dmarcPresent(false)
                .mxPresent(true)
                .build();

        assertEquals("CRITICAL", risco(r),
                "domínio que envia email e não tem SPF nem DMARC segue crítico");
    }

    @Test
    @DisplayName("consulta usa nome absoluto — a search list do host não pode entrar")
    void nomeSempreAbsoluto() {
        // Sem o ponto final, o dnsjava aplica a search list do /etc/resolv.conf e
        // pergunta por "santander.com.<search-do-cluster>", que volta NXDOMAIN.
        // Funciona na estação de trabalho e falha no container — a pior classe de bug.
        assertEquals("santander.com.", service.nomeAbsoluto("santander.com"));
        assertEquals("_dmarc.exemplo.com.", service.nomeAbsoluto("_dmarc.exemplo.com"));
        assertEquals("ja.absoluto.com.", service.nomeAbsoluto("ja.absoluto.com."),
                "não pode duplicar o ponto de quem já veio absoluto");
        assertEquals("com.espaco.", service.nomeAbsoluto("  com.espaco  "));
    }

    @Test
    @DisplayName("SPF duplicado não protege — RFC 7208 manda o receptor descartar todos")
    void spfDuplicadoNaoProtege() {
        DnsSecurityResult r = DnsSecurityResult.builder()
                .lookupFailed(false)
                .spfPresent(true).spfPolicy("INVALID")     // dois registros v=spf1
                .dmarcPresent(true).dmarcPolicy("STRONG")
                .mxPresent(true)
                .build();

        assertEquals("HIGH", risco(r),
                "registro que existe mas o receptor descarta equivale a não ter");
    }

    @Test
    @DisplayName("DMARC duplicado também não protege — RFC 7489")
    void dmarcDuplicadoNaoProtege() {
        DnsSecurityResult r = DnsSecurityResult.builder()
                .lookupFailed(false)
                .spfPresent(true).spfPolicy("STRONG")
                .dmarcPresent(true).dmarcPolicy("INVALID")
                .mxPresent(true)
                .build();

        assertEquals("HIGH", risco(r));
    }

    @Test
    @DisplayName("SPF e DMARC ambos duplicados caem no pior caso, como se faltassem")
    void ambosDuplicadosEhOPiorCaso() {
        DnsSecurityResult r = DnsSecurityResult.builder()
                .lookupFailed(false)
                .spfPresent(true).spfPolicy("INVALID")
                .dmarcPresent(true).dmarcPolicy("INVALID")
                .mxPresent(true)
                .build();

        assertEquals("CRITICAL", risco(r));
    }

    @Test
    @DisplayName("SPF -all + DMARC p=reject continua sendo o melhor caso")
    void configuracaoCorretaDaLow() {
        DnsSecurityResult r = DnsSecurityResult.builder()
                .lookupFailed(false)
                .spfPresent(true).spfPolicy("STRONG")
                .dmarcPresent(true).dmarcPolicy("STRONG")
                .build();

        assertEquals("LOW", risco(r));
    }
}
