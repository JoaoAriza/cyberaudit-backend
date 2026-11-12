package com.joao.cyberaudit.service;

import com.joao.cyberaudit.config.LocaleConfig;
import com.joao.cyberaudit.model.RiskLevel;
import com.joao.cyberaudit.model.SSLInfo;
import com.joao.cyberaudit.model.ScoreResult;
import com.joao.cyberaudit.model.SecurityIssue;
import com.joao.cyberaudit.model.TlsDetails;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.ResourceBundleMessageSource;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * BUG-11: HSTS ausente saía com severidade HIGH.
 *
 * Os 10 pontos estão certos (outras réguas públicas tiram até mais), mas o rótulo HIGH
 * acionava o piso de risco do ScoreService: qualquer issue HIGH trava o risco em, no
 * mínimo, MEDIUM. Um site sem nenhum outro achado, nota 90, saía "risco médio" só por
 * isso. HSTS ausente é endurecimento de transporte — o ataque exige posição de rede e
 * um acesso que comece em http:// —, não falha explorável de saída; MEDIUM é o rótulo
 * que as ferramentas de mercado usam no máximo.
 */
class HstsAusenteRotuloTest {

    private final ScoreService scoreService = new ScoreService(catalogoReal());

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

    /** Status como o HeaderService entrega. Tudo OK, salvo o que o teste trocar. */
    private static Map<String, String> headers(String hsts, String csp) {
        Map<String, String> h = new LinkedHashMap<>();
        h.put("Strict-Transport-Security", hsts);
        h.put("Content-Security-Policy",   csp);
        h.put("X-Frame-Options",           "OK (DENY)");
        h.put("X-Content-Type-Options",    "OK (nosniff)");
        h.put("Referrer-Policy",           "OK (no-referrer)");
        h.put("Permissions-Policy",        "OK (camera=())");
        return h;
    }

    private static final String HSTS_OK = "OK (max-age=31536000; includeSubDomains)";
    private static final String CSP_OK  = "OK";

    /** Alvo sem nenhum outro achado: HTTPS válido, TLS 1.3, security.txt, nada exposto. */
    private ScoreResult score(Map<String, String> headers) {
        SSLInfo    ssl = new SSLInfo(true, true, "2030-01-01", 300, "Certificado válido", 365);
        TlsDetails tls = new TlsDetails("TLSv1.3", "TLS_AES_256_GCM_SHA384", false, "OK");
        return scoreService.calculate(
                ssl, tls, headers, true,
                false, false, false, false, false, List.of(),
                null, List.of(), List.of(), false,
                List.of(), List.of(), true,
                List.of(), List.of(), null, null,
                List.of(), List.of(), List.of(), List.of(),
                List.of(), List.of(), List.of(), List.of(), List.of());
    }

    private static SecurityIssue issue(ScoreResult r, String id) {
        return r.getIssues().stream().filter(i -> id.equals(i.getId())).findFirst()
                .orElseThrow(() -> new AssertionError("issue " + id + " não saiu: " + r.getIssues()));
    }

    @Test
    @DisplayName("HSTS ausente sai MEDIUM")
    void rotuloMedium() {
        assertEquals("MEDIUM", issue(score(headers("MISSING", CSP_OK)), "HSTS_MISSING").getSeverity());
    }

    @Test
    @DisplayName("e continua custando 10 pontos")
    void continuaCustandoDez() {
        int semAchado = score(headers(HSTS_OK, CSP_OK)).getScore();
        int semHsts   = score(headers("MISSING", CSP_OK)).getScore();
        assertEquals(10, semAchado - semHsts);
    }

    @Test
    @DisplayName("site sem nenhum outro achado não vira risco MEDIUM só pela falta do HSTS")
    void naoTravaORisco() {
        ScoreResult r = score(headers("MISSING", CSP_OK));
        assertEquals(90, r.getScore());
        assertEquals(RiskLevel.SECURE, r.getRiskLevel(),
                "nota 90 é SECURE pela faixa; o piso de risco é para achado HIGH de verdade");
    }

    @Test
    @DisplayName("o piso de risco continua valendo para um achado HIGH (CSP ausente)")
    void pisoContinuaParaHigh() {
        ScoreResult r = score(headers(HSTS_OK, "MISSING"));
        assertEquals(90, r.getScore());
        assertEquals(RiskLevel.MEDIUM, r.getRiskLevel());
    }

    @Test
    @DisplayName("HSTS fraco segue MEDIUM, -5")
    void fracoInalterado() {
        ScoreResult r = score(headers("WEAK (max-age muito curto: 86400s)", CSP_OK));
        assertEquals("MEDIUM", issue(r, "HSTS_WEAK").getSeverity());
        assertEquals(95, r.getScore());
    }

    @Test
    @DisplayName("as duas recomendações apontam o mesmo alvo (1 ano) e o mesmo piso (30 dias)")
    void recomendacoesAlinhadas() {
        MessageCatalog catalog = catalogoReal();
        for (Locale idioma : new Locale[] { LocaleConfig.PADRAO, Locale.ENGLISH }) {
            LocaleContextHolder.setLocale(idioma);
            String ausente = catalog.recommendation("HSTS_MISSING");
            String fraco   = catalog.recommendation("HSTS_WEAK");
            assertTrue(ausente.contains("31536000") && fraco.contains("31536000"),
                    "o alvo é um só: " + ausente + " | " + fraco);
            assertTrue(ausente.contains("2592000") && fraco.contains("2592000"),
                    "e o piso abaixo do qual o laudo conta como fraco também: " + ausente + " | " + fraco);
            assertFalse(fraco.contains(">="), "o fraco não pode sugerir que 30 dias é a meta: " + fraco);
        }
    }
}
