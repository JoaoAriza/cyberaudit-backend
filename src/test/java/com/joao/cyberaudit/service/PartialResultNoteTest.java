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

    // ── O escopo do scan passivo ─────────────────────────────────────────────

    @Test
    @DisplayName("a nota do passivo diz quantas e quais sondas não foram aplicadas")
    void notaDoPassivoNomeiaOQueNaoRodou() {
        LocaleContextHolder.setLocale(Locale.forLanguageTag("pt-BR"));
        ScoreResult s = score();

        service().appendPassiveScopeNote(s, List.of(ScanCheck.PORT_SCAN, ScanCheck.SSRF));

        String nota = ultimaNota(s);
        assertTrue(nota.contains("2 verificações"), nota);
        assertTrue(nota.contains("Port scan"), nota);
        assertTrue(nota.contains("SSRF"), nota);
    }

    @Test
    @DisplayName("a nota do passivo avisa que o ativo pode dar nota MAIS BAIXA")
    void notaDoPassivoExplicaOSentidoDoDesconto() {
        // O ponto que a nota existe para desfazer: o score começa em 100 e só subtrai
        // o que acha. Passivo não roda as ativas, não acha, não desconta — e sai mais
        // alto que o ativo do mesmo host. Sem dizer isso, 92/100 se lê como veredito.
        LocaleContextHolder.setLocale(Locale.forLanguageTag("pt-BR"));
        ScoreResult s = score();

        service().appendPassiveScopeNote(s, List.of(ScanCheck.PORT_SCAN));

        assertTrue(ultimaNota(s).contains("mais baixa"),
                "a nota não explica o sentido da diferença: " + ultimaNota(s));
    }

    @SuppressWarnings("unchecked")
    private List<ScanCheck> checksAtivosDeProducao() {
        // A lista real que o orquestrador passa no scan passivo, não uma cópia
        // reconstruída aqui: se alguém reclassificar uma verificação no enum, este
        // teste acompanha em vez de continuar afirmando o número antigo.
        return (List<ScanCheck>) ReflectionTestUtils.getField(
                ScanOrchestrator.class, "CHECKS_ATIVOS");
    }

    @Test
    @DisplayName("a nota do passivo cobre as 10 sondas ativas de verdade, com os nomes")
    void notaDoPassivoUsaAListaDeProducao() {
        LocaleContextHolder.setLocale(Locale.forLanguageTag("pt-BR"));
        ScoreResult s = score();
        List<ScanCheck> ativos = checksAtivosDeProducao();

        service().appendPassiveScopeNote(s, ativos);
        String nota = ultimaNota(s);

        assertEquals(10, ativos.size(), "mudou a quantidade de sondas ativas");
        assertTrue(nota.contains("10 verificações"), nota);

        for (ScanCheck c : ativos) {
            assertTrue(nota.contains(service().nomeDe(c)),
                    c.name() + " não aparece na nota: " + nota);
        }

        // O contador vem de size() e a lista passa por distinct(): dois checks com o
        // mesmo nome de exibição fariam a nota dizer "10 verificações" e listar nove.
        // Contar vírgulas na frase não serve — a própria cauda dela tem uma.
        assertEquals(ativos.size(),
                ativos.stream().map(service()::nomeDe).distinct().count(),
                "duas verificações compartilham o nome de exibição — o contador da "
                        + "nota deixaria de fechar com a lista");
    }

    @Test
    @DisplayName("a nota do passivo não se confunde com a de falha de coleta")
    void escopoNaoEFalha() {
        // Causas diferentes, textos diferentes. Se as duas dissessem "não concluiu",
        // o cliente aprenderia a ler qualquer aviso como problema técnico nosso.
        LocaleContextHolder.setLocale(Locale.forLanguageTag("pt-BR"));

        ScoreResult falha = score();
        service().appendPartialNote(falha, List.of(ScanCheck.PORT_SCAN));

        ScoreResult escopo = score();
        service().appendPassiveScopeNote(escopo, List.of(ScanCheck.PORT_SCAN));

        assertFalse(ultimaNota(escopo).equals(ultimaNota(falha)));
        assertTrue(ultimaNota(falha).contains("não concluíram"), ultimaNota(falha));
        assertTrue(ultimaNota(escopo).contains("não foram aplicadas"), ultimaNota(escopo));
    }

    @Test
    @DisplayName("a nota do passivo segue o idioma do laudo")
    void notaDoPassivoSegueOIdioma() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        ScoreResult s = score();

        service().appendPassiveScopeNote(s, List.of(ScanCheck.PORT_SCAN));

        String nota = ultimaNota(s);
        assertTrue(nota.contains("were not applied"), nota);
        assertFalse(nota.contains("Scan passivo"), "sobrou português no laudo em inglês: " + nota);
    }

    @Test
    @DisplayName("scan ativo não ganha a nota de escopo")
    void ativoNaoGeraNotaDeEscopo() {
        ScoreResult s = score();

        service().appendPassiveScopeNote(s, List.of());

        assertEquals(1, s.getNotes().size());
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

    @SuppressWarnings("unchecked")
    private List<String> semVeredito(Map<String, String> moduleStatus) {
        return (List<String>) ReflectionTestUtils.invokeMethod(
                ScanOrchestrator.class, "semVeredito", moduleStatus);
    }

    @Test
    @DisplayName("scan passivo não deixa Open Redirect, CRLF, Path Traversal e SSRF como SECURE")
    void passivoNaoAfirmaSeguroSobreOQueNaoRodou() {
        // O defeito: a lista de achados desses quatro vinha vazia num scan passivo, e
        // vazio virava ✓ SECURE na barra lateral. Eles não entram no moduleStatus
        // porque nem rodam, então o modulosDegradados não os enxergava — o mesmo
        // "seguro que ninguém apurou" que o ⚠ NÃO VERIFICADO veio corrigir, só que
        // por outra causa, e por isso passou.
        var status = Map.of(ScanCheck.HTTP_FETCH.name(), "OK");

        assertTrue(semVeredito(status).containsAll(
                        List.of("redirect", "crlf", "traversal", "ssrf")),
                "módulo de sonda ativa ficaria verde num scan passivo: " + semVeredito(status));
    }

    @Test
    @DisplayName("o passivo soma as sondas não aplicadas às verificações que falharam")
    void escopoESomadoAFalha() {
        // As duas causas convergem no mesmo campo: para quem lê, "não concluiu" e
        // "não foi aplicada" dizem a mesma coisa sobre o que se pode confiar.
        var status = Map.of(
                ScanCheck.CVE.name(),        "TIMEOUT",
                ScanCheck.HTTP_FETCH.name(), "OK");

        var modulos = semVeredito(status);
        assertTrue(modulos.contains("cve"), modulos.toString());
        assertTrue(modulos.contains("ssrf"), modulos.toString());
        assertEquals(modulos.size(), modulos.stream().distinct().count(),
                "módulo repetido acenderia o mesmo aviso duas vezes: " + modulos);
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
