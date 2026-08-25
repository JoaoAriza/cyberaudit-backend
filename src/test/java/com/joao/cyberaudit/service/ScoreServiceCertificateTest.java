package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.SSLInfo;
import com.joao.cyberaudit.model.ScoreResult;
import com.joao.cyberaudit.model.TlsDetails;
import org.junit.jupiter.api.DisplayName;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Expiração de certificado julgada em PROPORÇÃO à vida útil.
 *
 * A regra anterior descontava de qualquer certificado com ≤90 dias restantes —
 * impossível de satisfazer, já que 90 dias é a vida inteira de um Let's Encrypt.
 */
class ScoreServiceCertificateTest {

    private final ScoreService scoreService = new ScoreService(catalogoReal());

    /**
     * Catálogo apontando para o messages.properties de verdade, não para um dublê.
     * Assim o teste também falha se uma chave sumir do arquivo — o texto passou a
     * viver fora do código, e nada mais garantiria que ele existe.
     */
    private static IssueCatalog catalogoReal() {
        var fonte = new ResourceBundleMessageSource();
        fonte.setBasename("messages");
        fonte.setDefaultEncoding("UTF-8");
        fonte.setFallbackToSystemLocale(false);
        return new IssueCatalog(fonte);
    }

    /** Headers "todos presentes", para isolar o efeito do certificado no score. */
    private static Map<String, String> headersOk() {
        return Map.of(
                "Strict-Transport-Security", "max-age=31536000",
                "Content-Security-Policy",   "default-src 'self'",
                "X-Frame-Options",           "DENY",
                "X-Content-Type-Options",    "nosniff",
                "Referrer-Policy",           "no-referrer");
    }

    private ScoreResult scoreFor(long daysRemaining, long totalValidityDays) {
        SSLInfo ssl = new SSLInfo(true, true, "2030-01-01",
                daysRemaining, "Certificado válido", totalValidityDays);
        TlsDetails tls = new TlsDetails("TLSv1.3", "TLS_AES_256_GCM_SHA384", false, "OK");

        return scoreService.calculate(
                ssl, tls, headersOk(), true,
                false, false, false, false, false, List.of(),
                null, List.of(), List.of(), false,
                List.of(), List.of(), true,
                List.of(), List.of(), null, null,
                List.of(), List.of(), List.of(), List.of(),
                List.of(), List.of(), List.of(), List.of(), List.of());
    }

    private boolean hasExpiringIssue(ScoreResult result) {
        return result.getIssues() != null && result.getIssues().stream()
                .anyMatch(i -> "SSL_EXPIRING_SOON".equals(i.getId()));
    }

    // ── Let's Encrypt: 90 dias de vida, certbot renova aos 30 ────────────────

    @Test
    @DisplayName("LE recém-emitido (90/90) não perde ponto — antes perdia 10")
    void letsEncryptRecemEmitido() {
        ScoreResult result = scoreFor(90, 90);

        assertFalse(hasExpiringIssue(result), "certificado novo não é problema");
    }

    @Test
    @DisplayName("LE na janela de renovação (30/90) não perde ponto — antes perdia 20")
    void letsEncryptNaJanelaDeRenovacao() {
        ScoreResult result = scoreFor(30, 90);

        assertFalse(hasExpiringIssue(result),
                "30 dias num certificado de 90 é exatamente quando o certbot renova");
    }

    @Test
    @DisplayName("LE com renovação quebrada (5/90) é sinalizado")
    void letsEncryptRenovacaoQuebrada() {
        ScoreResult result = scoreFor(5, 90);

        assertTrue(hasExpiringIssue(result),
                "abaixo de 9 dias num LE, a automação já falhou");
    }

    @Test
    @DisplayName("o score de um LE saudável é o mesmo em qualquer ponto do ciclo")
    void cicloCompletoNaoOscila() {
        int recemEmitido = scoreFor(89, 90).getScore();
        int meioDoCiclo  = scoreFor(45, 90).getScore();
        int preRenovacao = scoreFor(30, 90).getScore();

        assertEquals(recemEmitido, meioDoCiclo);
        assertEquals(recemEmitido, preRenovacao);
    }

    // ── Certificados curtos (a norma que vem por aí) ─────────────────────────

    @Test
    @DisplayName("certificado de 47 dias (norma 2029) opera sem penalidade")
    void certificadoCurtoNaoEPenalizado() {
        assertFalse(hasExpiringIssue(scoreFor(47, 47)));
        assertFalse(hasExpiringIssue(scoreFor(15, 47)));
        assertTrue(hasExpiringIssue(scoreFor(3, 47)), "abaixo de ~5 dias, sim");
    }

    // ── Certificado anual: o teto de 30 dias entra em ação ───────────────────

    @Test
    @DisplayName("anual de 398 dias alerta a 30 dias, não a 40 (teto absoluto)")
    void certificadoAnualUsaOTeto() {
        assertFalse(hasExpiringIssue(scoreFor(35, 398)));
        assertTrue(hasExpiringIssue(scoreFor(20, 398)));
    }

    @Test
    @DisplayName("CA interna com validade de 10 anos não alerta com meses de folga")
    void certificadoDeVidaMuitoLonga() {
        // Sem o teto, 10% de 3650 dias alertaria com um ANO restante.
        assertFalse(hasExpiringIssue(scoreFor(200, 3650)));
    }

    // ── Compatibilidade e limites ────────────────────────────────────────────

    @Test
    @DisplayName("vida útil desconhecida (scan antigo) cai para o piso de 7 dias")
    void vidaUtilDesconhecida() {
        assertFalse(hasExpiringIssue(scoreFor(20, 0)));
        assertTrue(hasExpiringIssue(scoreFor(3, 0)));
    }

    @Test
    @DisplayName("expirado continua sendo achado HIGH")
    void expiradoContinuaGrave() {
        SSLInfo ssl = new SSLInfo(true, true, "2020-01-01", 0, "Certificado válido", 90);
        TlsDetails tls = new TlsDetails("TLSv1.3", "TLS_AES_256_GCM_SHA384", false, "OK");

        ScoreResult result = scoreService.calculate(
                ssl, tls, headersOk(), true,
                false, false, false, false, false, List.of(),
                null, List.of(), List.of(), false,
                List.of(), List.of(), true,
                List.of(), List.of(), null, null,
                List.of(), List.of(), List.of(), List.of(),
                List.of(), List.of(), List.of(), List.of(), List.of());

        assertTrue(result.getIssues().stream()
                .anyMatch(i -> "SSL_EXPIRED".equals(i.getId()) && "HIGH".equals(i.getSeverity())));
    }
}
