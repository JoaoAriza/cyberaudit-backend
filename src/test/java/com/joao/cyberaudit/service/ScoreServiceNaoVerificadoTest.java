package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.SSLInfo;
import com.joao.cyberaudit.model.ScoreResult;
import com.joao.cyberaudit.model.TlsDetails;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.support.ResourceBundleMessageSource;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Módulo que não concluiu não pode virar desconto no score.
 *
 * O orquestrador espera os checks passivos com um teto de tempo e, no fim, lê
 * cada resultado com {@code getNow(default)}. Quem não terminou devolvia o
 * default — e, para o security.txt, o default "não encontrado" descontava 3
 * pontos e estampava AUSENTE no laudo. Foi assim que cyberauditapp.com apareceu
 * com "security.txt ausente: -3" tendo o arquivo publicado e respondendo 200.
 *
 * O tipo virou {@code Boolean} justamente para caber o terceiro estado: null é
 * "não verificado", e sobre isso o score não opina.
 */
class ScoreServiceNaoVerificadoTest {

    private final ScoreService scoreService = new ScoreService(catalogoReal());

    private static MessageCatalog catalogoReal() {
        var fonte = new ResourceBundleMessageSource();
        fonte.setBasename("messages");
        fonte.setDefaultEncoding("UTF-8");
        fonte.setFallbackToSystemLocale(false);
        return new MessageCatalog(fonte);
    }

    private static Map<String, String> headersOk() {
        return Map.of(
                "Strict-Transport-Security", "max-age=31536000",
                "Content-Security-Policy",   "default-src 'self'",
                "X-Frame-Options",           "DENY",
                "X-Content-Type-Options",    "nosniff",
                "Referrer-Policy",           "no-referrer");
    }

    /** Alvo impecável, variando só o veredito do security.txt. */
    private ScoreResult scoreCom(Boolean securityTxtPresent) {
        SSLInfo    ssl = new SSLInfo(true, true, "2030-01-01", 300, "Certificado válido", 365);
        TlsDetails tls = new TlsDetails("TLSv1.3", "TLS_AES_256_GCM_SHA384", false, "OK");

        return scoreService.calculate(
                ssl, tls, headersOk(), true,
                false, false, false, false, false, List.of(),
                null, List.of(), List.of(), false,
                List.of(), List.of(), securityTxtPresent,
                List.of(), List.of(), null, null,
                List.of(), List.of(), List.of(), List.of(),
                List.of(), List.of(), List.of(), List.of(), List.of());
    }

    @Test
    @DisplayName("security.txt não verificado não desconta")
    void naoVerificadoNaoDesconta() {
        assertEquals(scoreCom(true).getScore(), scoreCom(null).getScore(),
                "descontar por um módulo que não rodou é cobrar do alvo uma falha do scanner");
    }

    @Test
    @DisplayName("security.txt não verificado não gera achado no laudo")
    void naoVerificadoNaoGeraAchado() {
        boolean acusou = scoreCom(null).getIssues().stream()
                .anyMatch(i -> "SECURITY_TXT_MISSING".equals(i.getId()));

        assertTrue(!acusou, "sem ter verificado, o laudo não pode afirmar que o arquivo falta");
    }

    @Test
    @DisplayName("ausência confirmada continua descontando")
    void ausenciaConfirmadaAindaDesconta() {
        int presente = scoreCom(true).getScore();
        int ausente  = scoreCom(false).getScore();

        assertEquals(3, presente - ausente,
                "a penalidade real precisa sobreviver — o alvo do conserto era o null, não o false");
    }

    @Test
    @DisplayName("ausência confirmada continua gerando achado")
    void ausenciaConfirmadaGeraAchado() {
        boolean acusou = scoreCom(false).getIssues().stream()
                .anyMatch(i -> "SECURITY_TXT_MISSING".equals(i.getId()));

        assertTrue(acusou, "quando o módulo concluiu e o arquivo não está lá, o achado é legítimo");
    }
}
