package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.RiskLevel;
import com.joao.cyberaudit.model.ScanResult;
import com.joao.cyberaudit.model.ScoreResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Os templates de e-mail montam HTML por concatenação de String.formatted().
 * Sem escape, nome do usuário e URL escaneada entram crus no corpo do e-mail.
 */
class EmailServiceEscapingTest {

    private final EmailService service = new EmailService(null, catalogoReal());

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

    // ── Renderização de todos os templates ───────────────────────────────────

    /**
     * Os templates montam HTML com String.formatted e uma lista posicional longa —
     * o de degradação tem 21 argumentos. Errar a ORDEM não é erro de compilação:
     * ou estoura em runtime, ou troca dois textos de lugar em silêncio.
     *
     * Renderizar cada um aqui transforma o primeiro caso em teste vermelho. E as
     * asserções de conteúdo pegam o segundo, comparando com o catálogo.
     */
    /** Transporte de mentira: guarda o que seria enviado, para o teste inspecionar. */
    private static final class Caixa implements EmailSender {
        String assunto;
        String html;
        @Override public void send(String from, String to, String subject, String body) {
            this.assunto = subject;
            this.html    = body;
        }
    }

    private Caixa enviar(java.util.function.Consumer<EmailService> acao) {
        Caixa caixa = new Caixa();
        EmailService svc = new EmailService(caixa, catalogoReal());
        ReflectionTestUtils.setField(svc, "enabled", true);
        ReflectionTestUtils.setField(svc, "from", "noreply@teste.local");
        acao.accept(svc);
        return caixa;
    }

    @Test
    @DisplayName("todo template renderiza sem estourar e sem deixar placeholder para trás")
    void todosOsTemplatesRenderizam() {
        ScanResult scan = scanDeTeste("https://example.com");

        List<Caixa> enviados = List.of(
                enviar(s -> s.sendScanComplete("a@b.com", "Ana Souza", scan)),
                enviar(s -> s.sendDegradationAlert("a@b.com", "Ana Souza", "example.com",
                        80, 42, "HIGH", "certificado expirou", scan)),
                enviar(s -> s.sendOtpEmail("a@b.com", "Ana Souza", "123456")),
                enviar(s -> s.sendPasswordResetEmail("a@b.com", "Ana Souza",
                        "https://example.com/r/abc", 30)));

        // Chave não resolvida sai como caminho pontuado ("email.otp.footer").
        // Procurar só por "email." pegaria a própria prosa: "ignore este email."
        var chaveCrua = java.util.regex.Pattern.compile("\\b(email|issue|note)\\.[A-Za-z_]+\\.[A-Za-z_]+\\b");

        for (Caixa caixa : enviados) {
            assertNotNull(caixa.html, "o template não chegou a ser enviado");
            for (String texto : List.of(caixa.html, caixa.assunto)) {
                assertFalse(texto.contains("%s"), "sobrou placeholder: " + texto);
                assertFalse(texto.contains("%d"), "sobrou placeholder: " + texto);
                assertFalse(chaveCrua.matcher(texto).find(), "chave não resolvida: " + texto);
            }
        }
    }

    @Test
    @DisplayName("o assunto também segue o idioma, não só o corpo")
    void assuntoSegueOIdioma() {
        try {
            LocaleContextHolder.setLocale(Locale.ENGLISH);
            Caixa caixa = enviar(s -> s.sendScanComplete(
                    "a@b.com", "Ana", scanDeTeste("https://example.com")));

            assertTrue(caixa.assunto.startsWith("CyberAudit — Scan complete:"), caixa.assunto);
        } finally {
            LocaleContextHolder.resetLocaleContext();
        }
    }

    private static ScanResult scanDeTeste(String url) {
        ScoreResult score = new ScoreResult();
        score.setScore(42);
        score.setRiskLevel(RiskLevel.HIGH);
        score.setIssues(List.of());
        return ScanResult.builder().url(url).score(score).build();
    }

    @Test
    @DisplayName("o e-mail de scan sai no idioma pedido, assunto e corpo")
    void scanSegueOIdioma() {
        try {
            LocaleContextHolder.setLocale(Locale.ENGLISH);
            String html = buildScanHtml("Ana Souza", "https://example.com");

            assertTrue(html.contains("The scan of the domain below has finished:"), html);
            assertTrue(html.contains("lang=\"en\""), "o atributo lang deve seguir o idioma");
            assertFalse(html.contains("foi concluído"), "sobrou português no corpo");
        } finally {
            LocaleContextHolder.resetLocaleContext();
        }
    }

    @Test
    @DisplayName("sem nome, a saudação usa o termo genérico do idioma — não fica vazia")
    void saudacaoSemNome() {
        String html = buildScanHtml(null, "https://example.com");

        assertTrue(html.contains("usuário"), html.substring(0, Math.min(2000, html.length())));
    }

    private static MessageCatalog catalogoReal() {
        var fonte = new org.springframework.context.support.ResourceBundleMessageSource();
        fonte.setBasename("messages");
        fonte.setDefaultEncoding("UTF-8");
        fonte.setFallbackToSystemLocale(false);
        return new MessageCatalog(fonte);
    }
}
