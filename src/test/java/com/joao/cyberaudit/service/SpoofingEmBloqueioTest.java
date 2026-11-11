package com.joao.cyberaudit.service;

import com.joao.cyberaudit.config.LocaleConfig;
import com.joao.cyberaudit.model.DnsSecurityResult;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

/**
 * BUG-10: o risco de spoofing só saía LOW com SPF {@code -all} E DMARC {@code p=reject}.
 *
 * Um site de cliente com SPF {@code ~all} e DMARC {@code p=quarantine} — configuração
 * que barra email falso em qualquer provedor que avalia DMARC — perdia 6 pontos como
 * "proteção parcial", e trocar {@code p=none} por {@code p=quarantine} não mexia no
 * score. O inverso também existia: {@code +all} autoriza qualquer servidor, o email falso
 * passa alinhado pelo DMARC, e mesmo assim o domínio saía MEDIUM ao lado de um p=reject.
 *
 * A régua nova: com DMARC em bloqueio (reject, ou quarantine em 100% das mensagens),
 * o qualificador do SPF não muda o destino do email falso — fail, softfail e neutral
 * reprovam do mesmo jeito no DMARC. Só o {@code +all} muda, porque faz o falso PASSAR.
 */
class SpoofingEmBloqueioTest {

    private final DnsSecurityService service =
            new DnsSecurityService(mock(PublicSuffixService.class), catalogoReal());

    private static final String SPF_SOFTFAIL = "v=spf1 include:_spf.mail.hostinger.com ~all";
    private static final String SPF_HARDFAIL = "v=spf1 include:amazonses.com -all";

    private static MessageCatalog catalogoReal() {
        var fonte = new ResourceBundleMessageSource();
        fonte.setBasename("messages");
        fonte.setDefaultEncoding("UTF-8");
        fonte.setFallbackToSystemLocale(false);
        return new MessageCatalog(fonte);
    }

    @AfterEach
    void limpaIdioma() {
        LocaleContextHolder.resetLocaleContext();
    }

    /** Monta o resultado como o querySpf/queryDmarc montariam a partir dos registros. */
    private static DnsSecurityResult dominio(String spf, String dmarc, String politicaDmarc) {
        var b = DnsSecurityResult.builder().lookupFailed(false).mxPresent(true);
        if (spf != null) b.spfPresent(true).spfRecord(spf).spfPolicy(DnsSecurityService.politicaSpf(spf));
        else             b.spfPresent(false).spfPolicy("MISSING");
        if (dmarc != null) b.dmarcPresent(true).dmarcRecord(dmarc).dmarcPolicy(politicaDmarc);
        else               b.dmarcPresent(false).dmarcPolicy("MISSING");
        return b.build();
    }

    private String risco(DnsSecurityResult r) {
        return (String) ReflectionTestUtils.invokeMethod(service, "calculateRisk", r);
    }

    private String resumo(DnsSecurityResult r, Locale idioma) {
        r.setEmailSpoofingRisk(risco(r));
        LocaleContextHolder.setLocale(idioma);
        return (String) ReflectionTestUtils.invokeMethod(service, "buildSummary", r);
    }

    @Nested
    @DisplayName("DMARC em bloqueio + SPF válido = LOW")
    class DmarcEmBloqueio {

        @Test
        @DisplayName("o caso do laudo: SPF ~all + DMARC p=quarantine")
        void casoDoLaudo() {
            assertEquals("LOW", risco(dominio(SPF_SOFTFAIL, "v=DMARC1; p=quarantine", "MEDIUM")),
                    "quarantine em 100% manda o email falso para o spam em todo provedor que lê DMARC");
        }

        @Test
        @DisplayName("SPF ~all + DMARC p=reject")
        void softfailComReject() {
            assertEquals("LOW", risco(dominio(SPF_SOFTFAIL, "v=DMARC1; p=reject", "STRONG")),
                    "softfail reprova no DMARC igual a fail: o que decide o destino do falso é o p=");
        }

        @Test
        @DisplayName("SPF -all + DMARC p=quarantine")
        void hardfailComQuarantine() {
            assertEquals("LOW", risco(dominio(SPF_HARDFAIL, "v=DMARC1; p=quarantine", "MEDIUM")));
        }

        @Test
        @DisplayName("SPF ?all + DMARC p=reject — neutral também reprova no DMARC")
        void neutralComReject() {
            assertEquals("LOW", risco(dominio("v=spf1 a mx ?all", "v=DMARC1; p=reject", "STRONG")));
        }

        @Test
        @DisplayName("SPF com redirect= (sem all próprio) + DMARC p=reject")
        void redirectComReject() {
            assertEquals("LOW", risco(dominio("v=spf1 redirect=_spf.exemplo.com", "v=DMARC1; p=reject", "STRONG")),
                    "o all mora no registro de destino; o scanner não segue o redirect e não pode inventar +all");
        }

        @Test
        @DisplayName("SPF -all + DMARC p=reject continua LOW")
        void melhorCasoContinuaLow() {
            assertEquals("LOW", risco(dominio(SPF_HARDFAIL, "v=DMARC1; p=reject", "STRONG")));
        }

        @Test
        @DisplayName("DMARC p=none continua MEDIUM — não manda o receptor fazer nada")
        void pNoneContinuaMedium() {
            assertEquals("MEDIUM", risco(dominio(SPF_HARDFAIL, "v=DMARC1; p=none", "WEAK")));
        }
    }

    @Nested
    @DisplayName("pct= do DMARC (RFC 7489 §6.6.4)")
    class Pct {

        @Test
        @DisplayName("quarantine com pct=50 não é bloqueio: metade do email falso não sofre política nenhuma")
        void quarantineParcialEhMedium() {
            assertEquals("MEDIUM", risco(dominio(SPF_SOFTFAIL, "v=DMARC1; p=quarantine; pct=50", "MEDIUM")));
        }

        @Test
        @DisplayName("quarantine com pct=100 explícito é bloqueio")
        void quarantinePct100EhLow() {
            assertEquals("LOW", risco(dominio(SPF_SOFTFAIL, "v=DMARC1; p=quarantine; pct=100", "MEDIUM")));
        }

        @Test
        @DisplayName("reject com pct=25 segue bloqueio: o que fica fora do pct cai em quarantine")
        void rejectParcialContinuaLow() {
            assertEquals("LOW", risco(dominio(SPF_HARDFAIL, "v=DMARC1; p=reject; pct=25", "STRONG")));
        }

        @Test
        @DisplayName("reject com pct=0 equivale a quarantine em 100%")
        void rejectPctZeroEhLow() {
            assertEquals("LOW", risco(dominio(SPF_HARDFAIL, "v=DMARC1; p=reject; pct=0", "STRONG")));
        }

        @Test
        @DisplayName("pct inválido vale o padrão (100), como manda a RFC")
        void pctInvalidoValePadrao() {
            assertEquals("LOW", risco(dominio(SPF_SOFTFAIL, "v=DMARC1; p=quarantine; pct=abc", "MEDIUM")));
            assertEquals("LOW", risco(dominio(SPF_SOFTFAIL, "v=DMARC1; p=quarantine; pct=150", "MEDIUM")));
        }

        @Test
        @DisplayName("pct com espaço e maiúscula ainda é lido")
        void pctComEspaco() {
            assertEquals("MEDIUM", risco(dominio(SPF_SOFTFAIL, "v=DMARC1;p=quarantine; PCT = 10", "MEDIUM")));
        }
    }

    @Nested
    @DisplayName("SPF +all anula a proteção")
    class SpfAutorizaTodos {

        @Test
        @DisplayName("+all ao lado de DMARC p=reject é HIGH: o email falso passa alinhado")
        void maisAllComReject() {
            assertEquals("HIGH", risco(dominio("v=spf1 +all", "v=DMARC1; p=reject", "STRONG")));
        }

        @Test
        @DisplayName("all sem qualificador é +all (RFC 7208 §4.6.2)")
        void allSemQualificador() {
            assertEquals("HIGH", risco(dominio("v=spf1 a mx all", "v=DMARC1; p=reject", "STRONG")));
        }

        @Test
        @DisplayName("+all sem DMARC num domínio com MX é CRITICAL, como não ter nada")
        void maisAllSemDmarc() {
            assertEquals("CRITICAL", risco(dominio("v=spf1 include:_spf.exemplo.com +all", null, null)));
        }

        @Test
        @DisplayName("o resumo diz que o problema é o +all — e não manda configurar o DMARC que já existe")
        void resumoExplicaMaisAll() {
            var r = dominio("v=spf1 +all", "v=DMARC1; p=reject", "STRONG");
            assertTrue(resumo(r, LocaleConfig.PADRAO).contains("+all"));
            assertTrue(resumo(r, Locale.ENGLISH).contains("+all"));
        }
    }

    @ParameterizedTest(name = "{0} → {1}")
    @CsvSource(delimiter = '|', value = {
            "v=spf1 include:amazonses.com -all          | STRONG",
            "v=spf1 include:_spf.google.com ~all        | MEDIUM",
            "v=spf1 a mx ?all                           | WEAK",
            "v=spf1 +all                                | WEAK",
            "v=spf1 a mx all                            | WEAK",
            "v=spf1 ip4:192.0.2.1 -ALL                  | STRONG",
            "v=spf1 include:spf-all.exemplo.com ~all    | MEDIUM",
            "v=spf1 include:_spf.exemplo.com            | MEDIUM",
            "v=spf1 redirect=_spf.exemplo.com           | MEDIUM",
            "v=spf1 -all include:_spf.exemplo.com ~all  | STRONG",
    })
    @DisplayName("política do SPF sai do qualificador do termo all, não de substring")
    void politicaDoSpf(String registro, String esperado) {
        assertEquals(esperado, DnsSecurityService.politicaSpf(registro));
    }

    @Nested
    @DisplayName("textos do laudo")
    class Textos {

        @Test
        @DisplayName("MEDIUM não exige mais -all; explica que o DMARC não bloqueia")
        void resumoMediumNaoExigeHardfail() {
            var r = dominio(SPF_SOFTFAIL, "v=DMARC1; p=none", "WEAK");
            for (Locale idioma : new Locale[] { LocaleConfig.PADRAO, Locale.ENGLISH }) {
                String texto = resumo(r, idioma);
                assertFalse(texto.contains("-all"), "MEDIUM não é mais por falta de -all: " + texto);
                assertTrue(texto.contains("quarantine") && texto.contains("reject"),
                        "o caminho para LOW é o DMARC em bloqueio: " + texto);
                assertTrue(texto.contains("pct"), "quarantine parcial também cai aqui: " + texto);
            }
        }

        @Test
        @DisplayName("SPF duplicado com DMARC bom manda configurar o SPF, não o DMARC")
        void spfDuplicadoApontaSpf() {
            var r = DnsSecurityResult.builder().lookupFailed(false).mxPresent(true)
                    .spfPresent(true).spfPolicy("INVALID").spfRecord("2 registros SPF (inválido): ...")
                    .dmarcPresent(true).dmarcPolicy("STRONG").dmarcRecord("v=DMARC1; p=reject")
                    .build();
            String texto = resumo(r, LocaleConfig.PADRAO);
            assertTrue(texto.contains("SPF") && !texto.contains("DMARC"),
                    "o DMARC está certo; o que falta é um SPF que o receptor aceite: " + texto);
        }

        @Test
        @DisplayName("a recomendação aceita ~all e pede DMARC em bloqueio, nos dois idiomas")
        void recomendacaoAceitaSoftfail() {
            var catalog = catalogoReal();
            for (Locale idioma : new Locale[] { LocaleConfig.PADRAO, Locale.ENGLISH }) {
                LocaleContextHolder.setLocale(idioma);
                String texto = catalog.recommendation("DNS_EMAIL_SPOOFING");
                assertTrue(texto.contains("~all") && texto.contains("+all"),
                        "~all é aceito e +all é o que não pode: " + texto);
                assertTrue(texto.contains("quarantine"), "quarantine também é bloqueio: " + texto);
            }
        }
    }
}
