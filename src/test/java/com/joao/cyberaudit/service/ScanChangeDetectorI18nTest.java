package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.SSLInfo;
import com.joao.cyberaudit.model.ScanChange;
import com.joao.cyberaudit.model.ScanResult;
import com.joao.cyberaudit.model.ScoreResult;
import com.joao.cyberaudit.model.RiskLevel;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.ResourceBundleMessageSource;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.MissingResourceException;
import java.util.ResourceBundle;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * O módulo Changes segue o idioma do laudo.
 *
 * Era o último bolsão de português chumbado que chegava ao cliente: "Nova porta aberta
 * detectada", "Política SPF alterada", e os valores de antes/depois — "válido",
 * "aberta", "exposto". Um relatório em inglês mostrava a comparação entre dois scans
 * inteira em português.
 */
class ScanChangeDetectorI18nTest {

    private ScanChangeDetector detector() {
        var source = new ResourceBundleMessageSource();
        source.setBasename("messages");
        source.setDefaultEncoding("UTF-8");
        source.setFallbackToSystemLocale(false);
        return new ScanChangeDetector(new MessageCatalog(source));
    }

    @AfterEach
    void limpaIdioma() {
        LocaleContextHolder.resetLocaleContext();
    }

    private ScanResult comScore(int score) {
        return ScanResult.builder()
                .score(new ScoreResult(score, RiskLevel.MEDIUM, List.of(), List.of()))
                .build();
    }

    private ScanResult comSsl(boolean valido) {
        return ScanResult.builder()
                .score(new ScoreResult(70, RiskLevel.MEDIUM, List.of(), List.of()))
                // SSLInfo não tem builder — construtor legado (sem a vida útil total).
                .sslInfo(new SSLInfo(true, valido, null, 200, ""))
                .build();
    }

    private ScanResult comHeaders(Map<String, String> headers) {
        return ScanResult.builder()
                .score(new ScoreResult(70, RiskLevel.MEDIUM, List.of(), List.of()))
                .headers(headers)
                .build();
    }

    private String descricaoDe(List<ScanChange> mudancas, String categoria) {
        return mudancas.stream()
                .filter(c -> categoria.equals(c.getCategory()))
                .findFirst()
                .map(ScanChange::getDescription)
                .orElseThrow(() -> new AssertionError("sem mudança de " + categoria + " em " + mudancas));
    }

    // ── Descrição ────────────────────────────────────────────────────────────

    @Test
    @DisplayName("a queda de score é descrita no idioma do laudo")
    void scoreSegueOIdioma() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        assertTrue(descricaoDe(detector().detect(comScore(50), comScore(80)), "SCORE")
                .startsWith("Score fell from"));

        LocaleContextHolder.setLocale(Locale.forLanguageTag("pt-BR"));
        assertTrue(descricaoDe(detector().detect(comScore(50), comScore(80)), "SCORE")
                .startsWith("Score caiu de"));
    }

    @Test
    @DisplayName("o verbo do score sai de chave própria — interpolar texto não traduz")
    void subiuECaiuSaoChavesSeparadas() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        var mudancas = detector().detect(comScore(90), comScore(60));

        String d = descricaoDe(mudancas, "SCORE");
        assertTrue(d.startsWith("Score rose from"), d);
        assertFalse(d.contains("subiu"), "o verbo estava interpolado no format e escapava: " + d);
    }

    // ── Valores de antes/depois ──────────────────────────────────────────────

    @Test
    @DisplayName("os valores lado a lado também seguem o idioma")
    void valoresSeguemOIdioma() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        ScanChange ssl = detector().detect(comSsl(false), comSsl(true)).stream()
                .filter(c -> "SSL".equals(c.getCategory())).findFirst().orElseThrow();

        assertEquals("valid",   ssl.getOldValue());
        assertEquals("invalid", ssl.getNewValue());
        assertEquals("The SSL certificate became invalid", ssl.getDescription());
    }

    @Test
    @DisplayName("header removido é descrito no idioma, com o nome do header preservado")
    void headerRemovido() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        var mudancas = detector().detect(
                comHeaders(Map.of("Strict-Transport-Security", "MISSING")),
                comHeaders(Map.of("Strict-Transport-Security", "OK: max-age=31536000")));

        assertEquals("Strict-Transport-Security removed", descricaoDe(mudancas, "HEADERS"));
    }

    // ── O que NÃO é traduzido ────────────────────────────────────────────────

    @Test
    @DisplayName("field é rótulo técnico — a coluna não muda de idioma")
    void fieldNaoSegueOIdioma() {
        // Decisão registrada no javadoc do ScanChangeDetector: metade dos valores é
        // dado cru — nome do header, método HTTP, porta, caminho de arquivo — e as
        // duas telas renderizam a coluna em fonte monoespaçada, colada ao category,
        // que também é código. Traduzir só a metade que é prosa deixaria a coluna
        // metade em cada regime, que é pior que inteira em um só.
        List<String> pt = camposEm(Locale.forLanguageTag("pt-BR"));
        List<String> en = camposEm(Locale.ENGLISH);

        assertEquals(pt, en, "field virou prosa traduzida em uma das metades da coluna");
        assertTrue(pt.containsAll(
                        List.of("score", "certificate validity", "Strict-Transport-Security")),
                "o cenário deixou de exercitar os três regimes de field: " + pt);
    }

    /** Os campos das mudanças de score, SSL e header, resolvidos em um idioma só. */
    private List<String> camposEm(Locale idioma) {
        LocaleContextHolder.setLocale(idioma);
        ScanChangeDetector d = detector();

        return Stream.of(
                        d.detect(comScore(50), comScore(80)),
                        d.detect(comSsl(false), comSsl(true)),
                        d.detect(comHeaders(Map.of("Strict-Transport-Security", "MISSING")),
                                comHeaders(Map.of("Strict-Transport-Security", "OK: max-age=31536000"))))
                .flatMap(List::stream)
                .map(ScanChange::getField)
                .sorted()
                .toList();
    }

    // ── Cobertura do catálogo ────────────────────────────────────────────────

    @Test
    @DisplayName("toda chave de mudança e de valor existe nos dois idiomas")
    void catalogoCompletoNosDoisIdiomas() {
        // Mudança nova é fácil de escrever e fácil de esquecer no messages_en. Sem esta
        // trava, o cliente em inglês recebe "change.PORT_OPENED" cru no relatório.
        List<String> chaves = List.of(
                "change.SCORE_UP", "change.SCORE_DOWN", "change.SSL_INVALID",
                "change.SSL_VALID_AGAIN", "change.SSL_NEW_CERT", "change.SSL_WINDOW_30",
                "change.SSL_WINDOW_90", "change.HEADER_ADDED", "change.HEADER_REMOVED",
                "change.HEADER_CHANGED", "change.WAF_DETECTED", "change.WAF_GONE",
                "change.SPF_CHANGED", "change.DMARC_CHANGED", "change.SPOOFING_RISK",
                "change.HTTP_METHOD_NEW", "change.HTTP_METHOD_GONE", "change.PORT_OPENED",
                "change.PORT_CLOSED", "change.FILE_EXPOSED", "change.FILE_GONE",
                "change.SERVER_EXPOSED", "change.SERVER_HIDDEN", "change.TECH_CHANGED",
                "valor.valido", "valor.invalido", "valor.detectado", "valor.naoDetectado",
                "valor.habilitado", "valor.aberta", "valor.fechada", "valor.exposto",
                "valor.naoExposto", "valor.oculto", "valor.dias");

        for (String bundle : List.of("messages", "messages_en")) {
            ResourceBundle rb = ResourceBundle.getBundle(bundle, Locale.ROOT);
            for (String chave : chaves) {
                try {
                    assertFalse(rb.getString(chave).isBlank(), chave + " vazia em " + bundle);
                } catch (MissingResourceException e) {
                    throw new AssertionError(chave + " não existe em " + bundle + ".properties");
                }
            }
        }
    }
}
