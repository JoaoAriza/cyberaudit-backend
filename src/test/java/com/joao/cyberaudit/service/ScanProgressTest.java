package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.ScanCheck;
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
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * O registro de progresso do scan.
 *
 * Cada afirmação aqui corresponde a algo que o feed mostra na tela — e a algo que
 * ele mostraria errado se a regra sumisse.
 */
class ScanProgressTest {

    private ScanProgress progresso(boolean incluiAtivas) {
        var source = new ResourceBundleMessageSource();
        source.setBasename("messages");
        source.setDefaultEncoding("UTF-8");
        source.setFallbackToSystemLocale(false);
        return new ScanProgress(new MessageCatalog(source), incluiAtivas);
    }

    @AfterEach
    void limpaIdioma() {
        LocaleContextHolder.resetLocaleContext();
    }

    private String estadoDe(List<ScanProgress.Etapa> etapas, ScanCheck check) {
        return etapas.stream()
                .filter(e -> e.check().equals(check.name()))
                .findFirst()
                .map(ScanProgress.Etapa::state)
                .orElseThrow(() -> new AssertionError(check + " não está no instantâneo"));
    }

    // ── A lista que a tela recebe ────────────────────────────────────────────

    @Test
    @DisplayName("o feed nasce com a lista inteira pendente, antes de qualquer check rodar")
    void comecaTudoPendente() {
        var etapas = progresso(true).instantaneo();

        assertEquals(ScanCheck.values().length, etapas.size());
        assertTrue(etapas.stream().allMatch(e -> e.state().equals("PENDENTE")));
    }

    @Test
    @DisplayName("scan passivo não lista as verificações ativas")
    void passivoOmiteAsAtivas() {
        // Elas nunca vão rodar. Listadas, ficariam pendentes para sempre — e uma
        // linha que nunca sai do lugar faz o scan inteiro parecer travado.
        var etapas = progresso(false).instantaneo();

        assertTrue(etapas.stream().noneMatch(e -> e.phase().equals("ATIVA")));
        assertTrue(etapas.stream().anyMatch(e -> e.check().equals("HTTP_FETCH")));
    }

    @Test
    @DisplayName("o rótulo sai do catálogo, no idioma de quem perguntou")
    void rotuloSegueOIdiomaDaLeitura() {
        // Resolve na leitura, não na escrita: quem troca o idioma no meio do scan
        // vê o feed acompanhar na próxima resposta do polling.
        ScanProgress p = progresso(true);

        LocaleContextHolder.setLocale(Locale.ENGLISH);
        assertEquals("WAF detection", rotuloDe(p, ScanCheck.WAF));

        LocaleContextHolder.setLocale(Locale.forLanguageTag("pt-BR"));
        assertEquals("Detecção de WAF", rotuloDe(p, ScanCheck.WAF));
    }

    private String rotuloDe(ScanProgress p, ScanCheck check) {
        return p.instantaneo().stream()
                .filter(e -> e.check().equals(check.name()))
                .findFirst().orElseThrow().label();
    }

    // ── O que a tarefa anuncia sozinha ───────────────────────────────────────

    @Test
    @DisplayName("a tarefa marca rodando ao começar e OK ao terminar")
    void acompanhaMarcaOCicloDaTarefa() {
        ScanProgress p = progresso(true);

        var tarefa = p.acompanha(ScanCheck.ROBOTS, () -> {
            // Durante a execução, quem estiver fazendo polling vê RODANDO.
            assertEquals("RODANDO", estadoDe(p.instantaneo(), ScanCheck.ROBOTS));
            return "pronto";
        });

        assertEquals("PENDENTE", estadoDe(p.instantaneo(), ScanCheck.ROBOTS));
        assertEquals("pronto", tarefa.get());
        assertEquals("OK", estadoDe(p.instantaneo(), ScanCheck.ROBOTS));
    }

    @Test
    @DisplayName("tarefa que estoura marca falha e deixa a exceção seguir")
    void acompanhaNaoEngoleExcecao() {
        // O .exceptionally() do orquestrador é quem decide o valor de retorno. Se
        // este objeto engolisse a exceção, o check apareceria como OK e o resultado
        // viria vazio — pior que a falha visível.
        ScanProgress p = progresso(true);

        var tarefa = p.acompanha(ScanCheck.GRAPHQL, () -> {
            throw new IllegalStateException("alvo recusou");
        });

        assertThrows(IllegalStateException.class, tarefa::get);
        assertEquals("FALHOU", estadoDe(p.instantaneo(), ScanCheck.GRAPHQL));
    }

    // ── O acerto de contas no fim de cada fase ───────────────────────────────

    @Test
    @DisplayName("sincroniza tira do 'rodando' quem estourou o tempo")
    void timeoutDeixaDeParecerEmAndamento() {
        // Quem marca OK é a própria tarefa. A que não terminou não marca nada, e
        // ficaria girando no feed para sempre depois de o scan já ter acabado.
        ScanProgress p = progresso(true);
        p.registra(ScanCheck.SUBDOMAIN_TAKEOVER, ScanProgress.Estado.RODANDO);

        Map<String, String> moduleStatus = new LinkedHashMap<>();
        moduleStatus.put(ScanCheck.SUBDOMAIN_TAKEOVER.name(), "TIMEOUT");
        p.sincroniza(moduleStatus);

        assertEquals("FALHOU", estadoDe(p.instantaneo(), ScanCheck.SUBDOMAIN_TAKEOVER));
    }

    @Test
    @DisplayName("pulado é estado próprio — não é falha")
    void puladoNaoEFalha() {
        // Probe de injeção sem parâmetro para injetar é decisão do scan, não
        // problema do alvo. Mostrar como falha ensina o cliente a ignorar o feed.
        ScanProgress p = progresso(true);

        Map<String, String> moduleStatus = new LinkedHashMap<>();
        moduleStatus.put(ScanCheck.SSRF.name(), "SKIPPED");
        p.sincroniza(moduleStatus);

        assertEquals("PULADO", estadoDe(p.instantaneo(), ScanCheck.SSRF));
    }

    @Test
    @DisplayName("chave desconhecida no moduleStatus é ignorada, não derruba o scan")
    void chaveForaDoEnumNaoQuebra() {
        ScanProgress p = progresso(true);

        Map<String, String> moduleStatus = new LinkedHashMap<>();
        moduleStatus.put("CHECK_QUE_NAO_EXISTE", "OK");
        p.sincroniza(moduleStatus);

        assertEquals(ScanCheck.values().length, p.instantaneo().size());
    }

    // ── O caminho síncrono ───────────────────────────────────────────────────

    @Test
    @DisplayName("progresso desligado não observa nada e devolve o supplier intacto")
    void desligadoEInerte() {
        // /scan, o scan por API key e o agendado devolvem o resultado pronto: não há
        // polling para alimentar, e o custo de registrar seria puro desperdício.
        ScanProgress p = ScanProgress.desligado();

        java.util.function.Supplier<String> original = () -> "x";
        assertSame(original, p.acompanha(ScanCheck.WAF, original));
        assertTrue(p.instantaneo().isEmpty());

        p.registra(ScanCheck.WAF, ScanProgress.Estado.OK);
        p.sincroniza(Map.of(ScanCheck.WAF.name(), "OK"));
        assertTrue(p.instantaneo().isEmpty());
    }

    // ── Cobertura do catálogo ────────────────────────────────────────────────

    @Test
    @DisplayName("toda verificação tem rótulo nos dois idiomas")
    void todoCheckTemNome() {
        // Verificação nova sem entrada em check.* apareceria no feed como a chave
        // crua ("check.NOVO_PROBE") no meio da lista.
        for (Locale idioma : List.of(Locale.ENGLISH, Locale.forLanguageTag("pt-BR"))) {
            LocaleContextHolder.setLocale(idioma);
            for (var etapa : progresso(true).instantaneo()) {
                assertFalse(etapa.label().startsWith("check."),
                        etapa.check() + " sem rótulo em " + idioma + ": " + etapa.label());
            }
        }
    }
}
