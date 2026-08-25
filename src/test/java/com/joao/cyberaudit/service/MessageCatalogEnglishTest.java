package com.joao.cyberaudit.service;

import com.joao.cyberaudit.config.LocaleConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.ResourceBundleMessageSource;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * O catálogo em inglês.
 *
 * A tradução é fallback-tolerante: chave que falta no inglês resolve para o
 * português, então nada quebra — e é justamente por isso que o buraco passa
 * despercebido. Um laudo metade em cada idioma é pior que um erro, porque parece
 * funcionar. {@link #inglesCobreTodoOPortugues()} existe para isso.
 */
class MessageCatalogEnglishTest {

    private final MessageCatalog catalog = catalogoReal();

    private static MessageCatalog catalogoReal() {
        var fonte = new ResourceBundleMessageSource();
        fonte.setBasename("messages");
        fonte.setDefaultEncoding("UTF-8");
        fonte.setFallbackToSystemLocale(false);
        return new MessageCatalog(fonte);
    }

    @AfterEach
    void limparIdioma() {
        // ThreadLocal: sem limpar, o idioma vaza para o próximo teste da mesma thread.
        LocaleContextHolder.resetLocaleContext();
    }

    // ── Paridade entre os arquivos ───────────────────────────────────────────

    @Test
    @DisplayName("toda chave do português tem tradução em inglês")
    void inglesCobreTodoOPortugues() {
        Properties pt = carregar("messages.properties");
        Properties en = carregar("messages_en.properties");

        List<String> semTraducao = pt.stringPropertyNames().stream()
                .filter(chave -> !en.containsKey(chave))
                .sorted()
                .toList();

        assertTrue(semTraducao.isEmpty(),
                "sem tradução em messages_en.properties: " + semTraducao);
    }

    @Test
    @DisplayName("o inglês não tem chave que o português não tenha — erro de digitação")
    void inglesNaoInventaChave() {
        Properties pt = carregar("messages.properties");
        Properties en = carregar("messages_en.properties");

        List<String> orfas = en.stringPropertyNames().stream()
                .filter(chave -> !pt.containsKey(chave))
                .sorted()
                .toList();

        assertTrue(orfas.isEmpty(),
                "chave existe só no inglês (provável erro de digitação): " + orfas);
    }

    // ── Resolução por idioma ─────────────────────────────────────────────────

    @Test
    @DisplayName("com locale en, o texto sai em inglês")
    void ingles() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);

        assertEquals("HTTPS not supported", catalog.title("NO_HTTPS_SUPPORT"));
        assertEquals("HTTPS not supported: -40", catalog.note("NO_HTTPS_SUPPORT"));
        assertEquals("3 cookie(s) with security problems", catalog.title("INSECURE_COOKIES", 3));
    }

    @Test
    @DisplayName("en-GB também recebe inglês — a região não deve derrubar o idioma")
    void inglesRegional() {
        LocaleContextHolder.setLocale(Locale.forLanguageTag("en-GB"));

        assertEquals("HTTPS not supported", catalog.title("NO_HTTPS_SUPPORT"));
    }

    @Test
    @DisplayName("idioma sem catálogo cai no português, não no locale do servidor")
    void idiomaDesconhecidoCaiNoPortugues() {
        LocaleContextHolder.setLocale(Locale.FRENCH);

        assertEquals("HTTPS não suportado", catalog.title("NO_HTTPS_SUPPORT"));
    }

    @Test
    @DisplayName("apóstrofo sobrevive ao MessageFormat também no inglês")
    void apostrofoNoIngles() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);

        assertEquals("Insecure JWT in 'Authorization' (alg=none)",
                catalog.title("JWT", "Authorization", "none"));
    }

    @Test
    @DisplayName("a tradução realmente mudou o texto — não é cópia do português")
    void naoEhCopia() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        String en = catalog.impact("CSP_MISSING");
        LocaleContextHolder.setLocale(LocaleConfig.PADRAO);
        String pt = catalog.impact("CSP_MISSING");

        assertNotEquals(pt, en);
    }

    // ── Escolha explícita de idioma (?lang=) ─────────────────────────────────

    @Test
    @DisplayName("?lang= casa por idioma e ignora o que não temos")
    void parametroDeIdioma() {
        assertEquals(Locale.ENGLISH, LocaleConfig.doParametro("en"));
        assertEquals(Locale.ENGLISH, LocaleConfig.doParametro("en-US"));
        assertEquals(LocaleConfig.PADRAO, LocaleConfig.doParametro("pt"));
        assertEquals(LocaleConfig.PADRAO, LocaleConfig.doParametro("pt-PT"));

        // null devolve a decisão para o Accept-Language, em vez de forçar o padrão.
        assertEquals(null, LocaleConfig.doParametro("de"));
        assertEquals(null, LocaleConfig.doParametro(""));
        assertEquals(null, LocaleConfig.doParametro(null));
    }

    private static Properties carregar(String arquivo) {
        Properties p = new Properties();
        try (InputStream in = MessageCatalogEnglishTest.class.getClassLoader()
                .getResourceAsStream(arquivo)) {
            if (in == null) throw new AssertionError("arquivo não encontrado: " + arquivo);
            p.load(new InputStreamReader(in, StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new AssertionError("falha ao ler " + arquivo, e);
        }
        return p;
    }
}
