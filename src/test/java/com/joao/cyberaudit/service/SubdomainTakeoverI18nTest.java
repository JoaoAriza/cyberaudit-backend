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
 * O achado de subdomain takeover segue o idioma do laudo.
 *
 * O campo {@code vulnerability} aparece duas vezes no card — como resumo e como
 * linha "VULNERAB." — e era montado em português por concatenação. O nome do
 * serviço ("GitHub Pages", "AWS S3") é nome próprio e atravessa a frase; só a
 * moldura muda de idioma.
 */
class SubdomainTakeoverI18nTest {

    private static final List<String> CHAVES = List.of(
            "desc.TAKEOVER_UNCLAIMED", "desc.TAKEOVER_NO_RESPONSE",
            "evidence.TAKEOVER_REFUSED");

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
    @DisplayName("toda chave de takeover existe nos dois idiomas")
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
            assertNotEquals(pt.getString(chave), en.getString(chave), chave);
        }
    }

    @Test
    @DisplayName("o nome do serviço atravessa a frase sem ser traduzido")
    void nomeDoServicoAtravessaAFrase() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        assertEquals("CNAME points to an unclaimed GitHub Pages — the subdomain can be "
                        + "registered by an attacker",
                catalog.desc("TAKEOVER_UNCLAIMED", "GitHub Pages"));
        assertEquals("CNAME points to AWS S3 — the service does not respond",
                catalog.desc("TAKEOVER_NO_RESPONSE", "AWS S3"));
        assertEquals("Connection refused: unclaimed.github.io",
                catalog.evidence("TAKEOVER_REFUSED", "unclaimed.github.io"));

        LocaleContextHolder.setLocale(Locale.forLanguageTag("pt-BR"));
        assertEquals("CNAME aponta para GitHub Pages não reivindicado — subdomínio pode ser "
                        + "registrado por atacante",
                catalog.desc("TAKEOVER_UNCLAIMED", "GitHub Pages"));
        assertEquals("Conexão recusada: unclaimed.github.io",
                catalog.evidence("TAKEOVER_REFUSED", "unclaimed.github.io"));
    }
}
