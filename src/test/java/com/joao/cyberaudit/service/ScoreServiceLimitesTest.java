package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.SSLInfo;
import com.joao.cyberaudit.model.ScoreResult;
import com.joao.cyberaudit.model.TlsDetails;
import com.joao.cyberaudit.model.WafDetectionResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.support.ResourceBundleMessageSource;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * O score não sai de 0–100.
 *
 * O piso sempre existiu; o teto, não. O cálculo começa em 100 e o bônus de WAF
 * (seção 16 do ScoreService) SOMA até +8 — então um alvo sem nenhuma penalidade
 * passava de 100. O badge público de `cyberauditapp.com` exibiu **"104/100"** em
 * produção, em 2026-09-06, no endpoint que serve justamente para divulgar o
 * produto.
 *
 * Num produto que vende avaliação de segurança, uma nota impossível não é um
 * detalhe de formatação: ela põe em dúvida o número inteiro.
 */
class ScoreServiceLimitesTest {

    private final ScoreService scoreService = new ScoreService(catalogoReal());

    private static MessageCatalog catalogoReal() {
        var fonte = new ResourceBundleMessageSource();
        fonte.setBasename("messages");
        fonte.setDefaultEncoding("UTF-8");
        fonte.setFallbackToSystemLocale(false);
        return new MessageCatalog(fonte);
    }

    /** Headers todos presentes: zera o desconto por header ausente. */
    private static Map<String, String> headersOk() {
        return Map.of(
                "Strict-Transport-Security", "max-age=31536000",
                "Content-Security-Policy",   "default-src 'self'",
                "X-Frame-Options",           "DENY",
                "X-Content-Type-Options",    "nosniff",
                "Referrer-Policy",           "no-referrer");
    }

    /** WAF real, detectado com alta confiança e bloqueando payload: o maior bônus. */
    private static WafDetectionResult wafComBonusMaximo() {
        return WafDetectionResult.builder()
                .detected(true)
                .provider("Cloudflare")
                .category("WAF")
                .confidence("HIGH")
                .probeResponse("BLOCKED")
                .build();
    }

    private ScoreResult scoreCom(WafDetectionResult waf) {
        // Alvo impecável: HTTPS válido com folga, TLS 1.3, headers completos,
        // security.txt presente e nenhum achado em lugar nenhum.
        SSLInfo    ssl = new SSLInfo(true, true, "2030-01-01", 300, "Certificado válido", 365);
        TlsDetails tls = new TlsDetails("TLSv1.3", "TLS_AES_256_GCM_SHA384", false, "OK");

        return scoreService.calculate(
                ssl, tls, headersOk(), true,
                false, false, false, false, false, List.of(),
                null, List.of(), List.of(), false,
                List.of(), List.of(), true,
                List.of(), List.of(), null, waf,
                List.of(), List.of(), List.of(), List.of(),
                List.of(), List.of(), List.of(), List.of(), List.of());
    }

    @Test
    @DisplayName("alvo impecável com bônus de WAF não passa de 100")
    void bonusNaoEstouraOTeto() {
        // Sem o Math.min este caso devolve 108: 100 de partida + 8 do bônus
        // máximo (WAF real, confiança alta, payload bloqueado).
        assertEquals(100, scoreCom(wafComBonusMaximo()).getScore());
    }

    @Test
    @DisplayName("o bônus continua existindo — o teto não pode ter virado desconto")
    void bonusAindaCompensaAAusenciaDeWaf() {
        // Sem WAF detectado há penalidade de -3. A trava do teto não pode ter
        // apagado a diferença entre ter e não ter WAF: se os dois casos dessem o
        // mesmo número, o bônus teria sido neutralizado em vez de limitado.
        WafDetectionResult semWaf = WafDetectionResult.builder()
                .detected(false)
                .probeResponse("PASSED")
                .build();

        int comWaf = scoreCom(wafComBonusMaximo()).getScore();
        int nada   = scoreCom(semWaf).getScore();

        assertEquals(100, comWaf);
        assertTrue(nada < comWaf,
                "sem WAF deveria pontuar menos que com WAF, e veio " + nada + " contra " + comWaf);
    }

    @Test
    @DisplayName("o piso de zero continua valendo")
    void pisoPreservado() {
        // O Math.max(0, ...) é anterior a esta correção e não pode ter se perdido
        // no caminho: alvo sem HTTPS, sem headers e com TLS obsoleto acumula
        // penalidades muito além de 100 pontos.
        SSLInfo    ssl = new SSLInfo(false, false, null, 0, "Sem HTTPS", 0);
        TlsDetails tls = new TlsDetails("SSLv3", "NULL", true, "obsoleto");

        ScoreResult r = scoreService.calculate(
                ssl, tls, Map.of(), false,
                true, true, true, true, true, List.of(),
                null, List.of(), List.of(), true,
                List.of(), List.of(), false,
                List.of(), List.of(), null, null,
                List.of(), List.of(), List.of(), List.of(),
                List.of(), List.of(), List.of(), List.of(), List.of());

        assertEquals(0, r.getScore());
    }
}
