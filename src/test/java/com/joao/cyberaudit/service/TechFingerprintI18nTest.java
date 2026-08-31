package com.joao.cyberaudit.service;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.ResourceBundleMessageSource;

import java.util.List;
import java.util.Locale;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * A evidência da identificação de tecnologias segue o idioma do laudo.
 *
 * O {@link TechFingerprintService} montava as evidências em português direto no
 * código — "HTML: React fiber detectado", "cf-ray header presente". Elas aparecem
 * dentro do card do módulo, então o cliente lendo o laudo em inglês encontrava
 * ~20 linhas em português no meio dele.
 *
 * O que NÃO entrou no catálogo, de propósito: as linhas que só ecoam o protocolo
 * ({@code Server: nginx}, {@code Cookie: PHPSESSID}, {@code Meta generator: …}).
 * São o mesmo texto nos dois idiomas — traduzir seria inventar diferença.
 */
class TechFingerprintI18nTest {

    /** As chaves que o serviço referencia. Chave nova aqui, ou o teste não a cobre. */
    private static final List<String> CHAVES = List.of(
            "evidence.TECH_HEADER_PRESENT", "evidence.TECH_COOKIE_SESSION",
            "evidence.TECH_HTML_WP_CONTENT", "evidence.TECH_HTML_DRUPAL",
            "evidence.TECH_HTML_JOOMLA", "evidence.TECH_HTML_SHOPIFY",
            "evidence.TECH_HTML_GHOST", "evidence.TECH_HTML_WEBFLOW",
            "evidence.TECH_HTML_NUXT", "evidence.TECH_HTML_ANGULAR",
            "evidence.TECH_HTML_REACT", "evidence.TECH_HTML_VUE",
            "evidence.TECH_HTML_SVELTE", "evidence.TECH_HTML_BOOTSTRAP",
            "evidence.TECH_HTML_TAILWIND", "evidence.TECH_HTML_JQUERY",
            "evidence.TECH_HTML_VIEWSTATE", "evidence.TECH_HTML_THYMELEAF",
            "evidence.TECH_HTML_LARAVEL", "evidence.TECH_HTML_INERTIA");

    private final MessageCatalog catalog = catalogo();

    private static MessageCatalog catalogo() {
        var source = new ResourceBundleMessageSource();
        source.setBasename("messages");
        source.setDefaultEncoding("UTF-8");
        source.setFallbackToSystemLocale(false);
        return new MessageCatalog(source);
    }

    @AfterEach
    void limpaIdioma() {
        LocaleContextHolder.resetLocaleContext();
    }

    @Test
    @DisplayName("toda chave de evidência de tecnologia existe nos dois idiomas")
    void catalogoCompletoNosDoisIdiomas() {
        for (String bundle : List.of("messages", "messages_en")) {
            ResourceBundle rb = ResourceBundle.getBundle(bundle, Locale.ROOT);
            for (String chave : CHAVES) {
                try {
                    assertFalse(rb.getString(chave).isBlank(), chave + " vazia em " + bundle);
                } catch (MissingResourceException e) {
                    throw new AssertionError(chave + " não existe em " + bundle + ".properties");
                }
            }
        }
    }

    @Test
    @DisplayName("nenhuma tradução é cópia do português")
    void tudoFoiRealmenteTraduzido() {
        ResourceBundle pt = ResourceBundle.getBundle("messages", Locale.ROOT);
        ResourceBundle en = ResourceBundle.getBundle("messages_en", Locale.ROOT);

        for (String chave : CHAVES) {
            // Chave copiada do português é o modo silencioso de não traduzir: o
            // teste de paridade passa, e o laudo em inglês sai em português.
            assertNotEquals(pt.getString(chave), en.getString(chave), chave);
        }
    }

    @Test
    @DisplayName("o nome da tecnologia não é traduzido — só a moldura da frase")
    void nomeProprioAtravessaAFrase() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        assertEquals("cf-ray header present", catalog.evidence("TECH_HEADER_PRESENT", "cf-ray"));
        assertEquals("Cookie: Rails/Rack session", catalog.evidence("TECH_COOKIE_SESSION", "Rails/Rack"));
        assertEquals("HTML: React fiber detected", catalog.evidence("TECH_HTML_REACT"));

        LocaleContextHolder.setLocale(Locale.forLanguageTag("pt-BR"));
        assertEquals("header cf-ray presente", catalog.evidence("TECH_HEADER_PRESENT", "cf-ray"));
        assertEquals("Cookie: sessão do Rails/Rack", catalog.evidence("TECH_COOKIE_SESSION", "Rails/Rack"));
        assertEquals("HTML: fiber do React detectado", catalog.evidence("TECH_HTML_REACT"));
    }
}
