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
 * A mensagem do TLS negociado segue o idioma do laudo.
 *
 * O Frontend cola essa mensagem a uma nota que ele mesmo traduz — a linha do card
 * é {@code tls.message} seguido de {@code t("card.tls.pfsNota")}. Com a mensagem em
 * português e a nota em inglês, a emenda saía metade em cada idioma.
 */
class TlsVersionI18nTest {

    private static final List<String> CHAVES = List.of(
            "desc.TLS_INVALID_HOST", "desc.TLS_INSPECT_FAILED", "desc.TLS_DEPRECATED",
            "desc.TLS_12", "desc.TLS_13", "desc.TLS_OTHER");

    private TlsVersionService servico() {
        var source = new ResourceBundleMessageSource();
        source.setBasename("messages");
        source.setDefaultEncoding("UTF-8");
        source.setFallbackToSystemLocale(false);
        return new TlsVersionService(new MessageCatalog(source));
    }

    @AfterEach
    void limpaIdioma() {
        LocaleContextHolder.resetLocaleContext();
    }

    @Test
    @DisplayName("toda chave de TLS existe nos dois idiomas")
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
    @DisplayName("cada protocolo negociado tem sua frase nos dois idiomas")
    void mensagemPorProtocolo() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        assertEquals("TLSv1.1 is deprecated (RFC 8996). Vulnerable to POODLE/BEAST.",
                servico().buildMessage("TLSv1.1", "TLS_RSA_WITH_AES_128_CBC_SHA", true));
        assertEquals("TLS 1.2 — secure. TLS 1.3 offers better forward secrecy.",
                servico().buildMessage("TLSv1.2", "TLS_AES_128_GCM_SHA256", false));
        assertEquals("TLS 1.3 — current protocol. Cipher: TLS_AES_256_GCM_SHA384",
                servico().buildMessage("TLSv1.3", "TLS_AES_256_GCM_SHA384", false));
        assertEquals("Protocol: SSLv2. Cipher: NULL",
                servico().buildMessage("SSLv2", "NULL", false));

        LocaleContextHolder.setLocale(Locale.forLanguageTag("pt-BR"));
        assertEquals("TLSv1.1 é deprecated (RFC 8996). Vulnerável a POODLE/BEAST.",
                servico().buildMessage("TLSv1.1", "TLS_RSA_WITH_AES_128_CBC_SHA", true));
        assertEquals("TLS 1.3 — protocolo atual. Cipher: TLS_AES_256_GCM_SHA384",
                servico().buildMessage("TLSv1.3", "TLS_AES_256_GCM_SHA384", false));
    }

    @Test
    @DisplayName("host em branco não chega ao handshake e ainda assim responde no idioma")
    void hostInvalido() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        assertEquals("Invalid host", servico().inspect("  ", 443).getMessage());

        LocaleContextHolder.setLocale(Locale.forLanguageTag("pt-BR"));
        assertEquals("Host inválido", servico().inspect(null, 443).getMessage());
    }
}
