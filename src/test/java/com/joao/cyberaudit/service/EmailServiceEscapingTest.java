package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.RiskLevel;
import com.joao.cyberaudit.model.ScanResult;
import com.joao.cyberaudit.model.ScoreResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Os templates de e-mail montam HTML por concatenação de String.formatted().
 * Sem escape, nome do usuário e URL escaneada entram crus no corpo do e-mail.
 */
class EmailServiceEscapingTest {

    private final EmailService service = new EmailService(null);

    private String escape(String raw) {
        return (String) ReflectionTestUtils.invokeMethod(service, "escHtml", raw);
    }

    private String buildScanHtml(String name, String url) {
        ScoreResult score = new ScoreResult();
        score.setScore(42);
        score.setRiskLevel(RiskLevel.HIGH);
        score.setIssues(List.of());

        ScanResult result = ScanResult.builder().url(url).score(score).build();

        return (String) ReflectionTestUtils.invokeMethod(
                service, "buildHtml", name, url, 42, "HIGH", "#ff6b35", result);
    }

    @Test
    @DisplayName("escHtml neutraliza tags e também aspas (contexto de atributo)")
    void escapaTagsEAspas() {
        String escaped = escape("<script>alert('x')</script>\"onload=\"y");

        assertFalse(escaped.contains("<script>"), escaped);
        assertFalse(escaped.contains("\""), "aspas duplas escapariam de um atributo: " + escaped);
        assertFalse(escaped.contains("'"), "aspas simples escapariam de um atributo: " + escaped);
        assertTrue(escaped.contains("&lt;script&gt;"), escaped);
    }

    @Test
    @DisplayName("escHtml trata null e preserva texto comum")
    void tratamentoBasico() {
        assertTrue(escape(null).isEmpty());
        assertTrue(escape("Relatório de segurança").contains("Relatório de segurança"));
    }

    @Test
    @DisplayName("ampersand é escapado antes dos demais — sem duplo escape")
    void ampersandPrimeiro() {
        assertTrue(escape("a & b").contains("a &amp; b"));
        // Se o & fosse escapado por último, "&lt;" viraria "&amp;lt;"
        assertTrue(escape("<").equals("&lt;"), escape("<"));
    }

    @Test
    @DisplayName("URL escaneada não injeta HTML no e-mail de scan concluído")
    void urlNaoInjetaHtml() {
        String html = buildScanHtml("Fulano",
                "https://example.com/?q=<img src=x onerror=alert(1)>");

        assertFalse(html.contains("<img src=x"), "a URL entrou crua no corpo do e-mail");
        assertTrue(html.contains("&lt;img src=x"), "a URL deveria aparecer escapada");
    }

    @Test
    @DisplayName("nome do usuário não injeta HTML no e-mail de scan concluído")
    void nomeNaoInjetaHtml() {
        String html = buildScanHtml("<script>alert(1)</script> Silva", "https://example.com");

        assertFalse(html.contains("<script>alert(1)</script>"), "o nome entrou cru no corpo do e-mail");
    }
}
