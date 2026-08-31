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
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A descrição do risco de cada método HTTP segue o idioma do laudo.
 *
 * O texto morava dentro de um {@code static final Map} — resolver ali congelaria o
 * idioma no carregamento da classe, e o primeiro scan decidiria pelos outros. Agora
 * o mapa guarda a chave, e a frase é resolvida por requisição.
 */
class HttpMethodI18nTest {

    private HttpMethodService servico() {
        var source = new ResourceBundleMessageSource();
        source.setBasename("messages");
        source.setDefaultEncoding("UTF-8");
        source.setFallbackToSystemLocale(false);
        return new HttpMethodService(new MessageCatalog(source));
    }

    @AfterEach
    void limpaIdioma() {
        LocaleContextHolder.resetLocaleContext();
    }

    @Test
    @DisplayName("todo método testado tem descrição nos dois idiomas")
    void catalogoCompletoNosDoisIdiomas() {
        // Percorre o mapa do serviço, não uma cópia da lista: método perigoso novo
        // entra aqui sozinho, e sem tradução o teste cai.
        for (String bundle : List.of("messages", "messages_en")) {
            ResourceBundle rb = ResourceBundle.getBundle(bundle, Locale.ROOT);
            for (String chave : HttpMethodService.chavesDeRisco()) {
                try {
                    assertFalse(rb.getString("desc." + chave).isBlank(),
                            chave + " vazia em " + bundle);
                } catch (MissingResourceException e) {
                    throw new AssertionError("desc." + chave + " não existe em " + bundle);
                }
            }
            assertFalse(rb.getString("desc.METHOD_REQUIRES_AUTH").isBlank());
        }
    }

    @Test
    @DisplayName("nenhuma tradução é cópia do português")
    void tudoFoiRealmenteTraduzido() {
        ResourceBundle pt = ResourceBundle.getBundle("messages", Locale.ROOT);
        ResourceBundle en = ResourceBundle.getBundle("messages_en", Locale.ROOT);

        for (String chave : HttpMethodService.chavesDeRisco()) {
            assertNotEquals(pt.getString("desc." + chave), en.getString("desc." + chave), chave);
        }
    }

    @Test
    @DisplayName("a descrição do risco sai no idioma do laudo")
    void descricaoSegueOIdioma() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        assertEquals("PUT enabled may allow arbitrary file upload.",
                servico().describeRisk("METHOD_PUT", false));

        LocaleContextHolder.setLocale(Locale.forLanguageTag("pt-BR"));
        assertEquals("PUT habilitado pode permitir upload de arquivos arbitrários.",
                servico().describeRisk("METHOD_PUT", false));
    }

    @Test
    @DisplayName("a ressalva de autenticação envolve a frase inteira, no mesmo idioma")
    void ressalvaDeAutenticacao() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        String en = servico().describeRisk("METHOD_TRACE", true);
        assertTrue(en.startsWith("TRACE enabled allows Cross-Site Tracing"), en);
        assertTrue(en.endsWith("(requires authentication)"), en);

        LocaleContextHolder.setLocale(Locale.forLanguageTag("pt-BR"));
        String pt = servico().describeRisk("METHOD_TRACE", true);
        assertTrue(pt.startsWith("TRACE habilitado permite Cross-Site Tracing"), pt);
        assertTrue(pt.endsWith("(requer autenticação)"), pt);
    }
}
