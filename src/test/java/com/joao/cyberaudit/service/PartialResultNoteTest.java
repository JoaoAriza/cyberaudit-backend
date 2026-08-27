package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.RiskLevel;
import com.joao.cyberaudit.model.ScanCheck;
import com.joao.cyberaudit.model.ScoreResult;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A nota de resultado parcial diz QUAL verificação não concluiu.
 *
 * O defeito que motivou: um scan com timeout na busca da página mostrava
 * "1 verificação(ões) não concluída(s)" e nada mais. O leitor não tinha como saber
 * qual módulo olhar com desconfiança — e a barra lateral, do lado, exibia ✓ verde
 * naquele mesmo módulo. Duas afirmações contraditórias sobre a mesma coisa.
 *
 * A nota também estava chumbada em português e saía assim no meio de um laudo em
 * inglês; por isso os testes abaixo exercitam os dois idiomas.
 */
class PartialResultNoteTest {

    private ScoreService service() {
        var source = new ResourceBundleMessageSource();
        source.setBasename("messages");
        source.setDefaultEncoding("UTF-8");
        source.setFallbackToSystemLocale(false);
        return new ScoreService(new MessageCatalog(source));
    }

    private ScoreResult score() {
        return new ScoreResult(70, RiskLevel.MEDIUM, new ArrayList<>(List.of("nota anterior")), List.of());
    }

    private String ultimaNota(ScoreResult s) {
        return s.getNotes().get(s.getNotes().size() - 1);
    }

    /**
     * O idioma é de thread, não global.
     *
     * Trocar {@code Locale.getDefault()} vazaria para os outros testes do mesmo JVM e
     * daria falha intermitente conforme a ordem de execução.
     */
    @AfterEach
    void limpaIdioma() {
        LocaleContextHolder.resetLocaleContext();
    }

    // ── O que a nota tem de dizer ────────────────────────────────────────────

    @Test
    @DisplayName("a nota nomeia a verificação que não concluiu")
    void notaNomeiaAVerificacao() {
        LocaleContextHolder.setLocale(Locale.forLanguageTag("pt-BR"));
        ScoreResult s = score();

        service().appendPartialNote(s, List.of(ScanCheck.HTTP_FETCH));

        assertTrue(ultimaNota(s).contains("Busca da página / headers"),
                "sem o nome, o cliente não sabe de qual módulo desconfiar: " + ultimaNota(s));
    }

    @Test
    @DisplayName("mais de uma verificação entram todas, separadas")
    void variasVerificacoesAparecemJuntas() {
        LocaleContextHolder.setLocale(Locale.forLanguageTag("pt-BR"));
        ScoreResult s = score();

        service().appendPartialNote(s, List.of(ScanCheck.HTTP_FETCH, ScanCheck.PORT_SCAN));

        assertTrue(ultimaNota(s).contains("Busca da página / headers"), ultimaNota(s));
        assertTrue(ultimaNota(s).contains("Port scan"), ultimaNota(s));
    }

    @Test
    @DisplayName("scan completo não ganha nota nenhuma")
    void scanCompletoNaoGeraNota() {
        ScoreResult s = score();

        service().appendPartialNote(s, List.of());

        assertEquals(1, s.getNotes().size(), "nota de resultado parcial sem resultado parcial é ruído");
    }

    // ── Idioma ───────────────────────────────────────────────────────────────

    @Test
    @DisplayName("a nota segue o idioma do laudo — antes saía em português no relatório em inglês")
    void notaSegueOIdioma() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        ScoreResult s = score();

        service().appendPartialNote(s, List.of(ScanCheck.HTTP_FETCH));

        String nota = ultimaNota(s);
        assertTrue(nota.contains("Page fetch / headers"), nota);
        assertFalse(nota.contains("Resultado parcial"), "sobrou português no laudo em inglês: " + nota);
    }

    // ── A armadilha ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("toda verificação tem nome nos dois catálogos — sem isso o laudo mostra a chave crua")
    void todaVerificacaoTemNomeNosDoisIdiomas() {
        // Verificação nova entra no enum e é fácil esquecer do catálogo. O
        // MessageCatalog devolve a própria chave quando não acha, então o cliente
        // veria "check.SSRF" no meio do relatório em vez de "SSRF".
        for (String bundle : List.of("messages", "messages_en")) {
            ResourceBundle rb = ResourceBundle.getBundle(bundle, Locale.ROOT);
            for (ScanCheck c : ScanCheck.values()) {
                String chave = "check." + c.name();
                try {
                    assertFalse(rb.getString(chave).isBlank(), chave + " está vazia em " + bundle);
                } catch (MissingResourceException e) {
                    throw new AssertionError(chave + " não existe em " + bundle + ".properties");
                }
            }
        }
    }

    // ── Do estado das verificações para o aviso na barra lateral ─────────────

    @SuppressWarnings("unchecked")
    private List<String> modulosDegradados(Map<String, String> moduleStatus) {
        return (List<String>) ReflectionTestUtils.invokeMethod(
                ScanOrchestrator.class, "modulosDegradados", moduleStatus);
    }

    @Test
    @DisplayName("verificação com erro acende o módulo dela — é o caso do print: fetch falhou, headers ✓ verde")
    void erroAcendeOModuloCorrespondente() {
        var status = Map.of(
                ScanCheck.HTTP_FETCH.name(), "ERROR",
                ScanCheck.DNS_EMAIL.name(),  "OK");

        assertEquals(List.of("headers"), modulosDegradados(status));
    }

    @Test
    @DisplayName("verificações do mesmo módulo acendem o módulo uma vez só")
    void mesmoModuloNaoDuplica() {
        // WAF, CORS e port scan são todas "active": três timeouts não podem virar
        // três avisos no mesmo item da barra lateral.
        var status = Map.of(
                ScanCheck.WAF.name(),       "TIMEOUT",
                ScanCheck.CORS.name(),      "TIMEOUT",
                ScanCheck.PORT_SCAN.name(), "TIMEOUT");

        assertEquals(List.of("active"), modulosDegradados(status));
    }

    @Test
    @DisplayName("SKIPPED não acende aviso — é decisão do scan, não falha de coleta")
    void skippedNaoEDegradacao() {
        // Probe de injeção sem parâmetro para injetar é pulado de propósito. Avisar
        // aqui viraria ruído em todo scan passivo e ensinaria o cliente a ignorar o
        // aviso justamente quando ele importa.
        var status = Map.of(
                ScanCheck.REFLECTED_XSS.name(), "SKIPPED",
                ScanCheck.SSRF.name(),          "SKIPPED");

        assertTrue(modulosDegradados(status).isEmpty());
    }

    @Test
    @DisplayName("chave desconhecida é ignorada — resultado gravado antes do enum existir")
    void chaveAntigaNaoQuebra() {
        // O histórico guarda o ScanResult inteiro em JSON. Registro anterior a esta
        // mudança tem a chave em prosa ("HTTP fetch / headers"); ela não casa com o
        // enum e tem de ser ignorada, não estourar ao abrir o laudo antigo.
        var status = Map.of(
                "HTTP fetch / headers", "ERROR",
                ScanCheck.CVE.name(),   "TIMEOUT");

        assertEquals(List.of("cve"), modulosDegradados(status));
    }

    @Test
    @DisplayName("todo módulo apontado pelas verificações existe na barra lateral do Frontend")
    void moduloUiEDaListaConhecida() {
        // A lista espelha os ids de MODULE_INFO no App.tsx. Um id fora dela vira aviso
        // que nunca aparece — falha silenciosa, que é o modo de falhar que este
        // conjunto de mudanças existe para eliminar.
        List<String> modulosDaInterface = List.of(
                "issues", "headers", "transport", "http", "redirect", "dirlist", "recon",
                "cert", "takeover", "tech", "cookies", "cve", "changes", "apidocs",
                "graphql", "jwt", "crlf", "sourcemap", "hostheader", "ssrf", "traversal",
                "active", "compliance");

        for (ScanCheck c : ScanCheck.values()) {
            assertTrue(modulosDaInterface.contains(c.moduloUi()),
                    c.name() + " aponta para o módulo '" + c.moduloUi()
                            + "', que não existe na barra lateral");
        }
    }
}
