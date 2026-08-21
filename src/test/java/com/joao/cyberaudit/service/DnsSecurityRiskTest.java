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
