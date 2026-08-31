package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.WafDetectionResult;
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
 * A detecção de WAF segue o idioma do laudo.
 *
 * Este serviço tinha português em dois lugares, e o segundo é o que dói: além da
 * evidência de uma linha, o {@code summary} é um parágrafo inteiro que aparece no
 * card — "WAF não confirmado via headers. O site pode usar proteção sem expor…".
 * O laudo em inglês trazia esse parágrafo em português.
 *
 * O resumo tinha um rótulo de tipo ("CDN (sem WAF nativo)") concatenado no meio da
 * frase. Concatenar fragmento traduzido é o mesmo erro do verbo do score no módulo
 * Changes — por isso cada combinação de tipo × confiança virou uma chave inteira.
 */
class WafDetectionI18nTest {

    private static final List<String> CHAVES = List.of(
            "evidence.WAF_HEADER", "evidence.WAF_VIA", "evidence.WAF_VIA_FASTLY",
            "evidence.WAF_PAYLOAD_BLOCKED", "evidence.WAF_NONE", "evidence.WAF_ERROR",
            "desc.WAF_NOT_CONFIRMED", "desc.WAF_HIGH_WAF", "desc.WAF_HIGH_CDN",
            "desc.WAF_HIGH_BOTH", "desc.WAF_MEDIUM", "desc.WAF_LOW",
            "desc.WAF_DETECTED_WAF", "desc.WAF_DETECTED_CDN", "desc.WAF_DETECTED_BOTH");

    /** {@code Via: {0}} é eco do protocolo — é a mesma linha nos dois idiomas. */
    private static final List<String> ECO_DO_PROTOCOLO = List.of("evidence.WAF_VIA");

    private WafDetectionService servico() {
        var source = new ResourceBundleMessageSource();
        source.setBasename("messages");
        source.setDefaultEncoding("UTF-8");
        source.setFallbackToSystemLocale(false);
        return new WafDetectionService(new MessageCatalog(source));
    }

    @AfterEach
    void limpaIdioma() {
        LocaleContextHolder.resetLocaleContext();
    }

    private WafDetectionResult resultado(boolean detectado, String categoria, String confianca) {
        return WafDetectionResult.builder()
                .detected(detectado)
                .provider("Cloudflare")
                .category(categoria)
                .confidence(confianca)
                .probeResponse("PASSED")
                .build();
    }

    // ── Cobertura do catálogo ────────────────────────────────────────────────

    @Test
    @DisplayName("toda chave de WAF existe nos dois idiomas")
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
            if (ECO_DO_PROTOCOLO.contains(chave)) continue;
            assertNotEquals(pt.getString(chave), en.getString(chave), chave);
        }
    }

    // ── O parágrafo do resumo ────────────────────────────────────────────────

    @Test
    @DisplayName("o resumo de 'não detectado' sai no idioma do laudo")
    void naoDetectadoSegueOIdioma() {
        var r = resultado(false, null, null);

        LocaleContextHolder.setLocale(Locale.ENGLISH);
        assertEquals("No WAF confirmed via headers. The site may run protection without "
                        + "exposing identifying headers (common in enterprise infrastructure), "
                        + "or may have no WAF at all. Payload probe: PASSED.",
                servico().buildSummary(r));

        LocaleContextHolder.setLocale(Locale.forLanguageTag("pt-BR"));
        assertEquals("WAF não confirmado via headers. O site pode usar proteção sem expor "
                        + "headers identificadores (prática comum em infraestruturas enterprise), "
                        + "ou pode não ter WAF. Probe com payload: PASSED.",
                servico().buildSummary(r));
    }

    @Test
    @DisplayName("cada combinação de tipo e confiança resolve para uma frase, não para a chave crua")
    void todaCombinacaoResolve() {
        // Chave montada por concatenação ("WAF_HIGH_" + tipo) não é vista pelo
        // compilador: um typo sai como "desc.WAF_HIGH_CDN" cru dentro do card.
        LocaleContextHolder.setLocale(Locale.ENGLISH);

        for (String categoria : List.of("WAF", "CDN", "BOTH")) {
            for (String confianca : List.of("HIGH", "MEDIUM", "LOW", "")) {
                String resumo = servico().buildSummary(resultado(true, categoria, confianca));
                assertFalse(resumo.startsWith("desc."),
                        "chave crua no resumo (" + categoria + "/" + confianca + "): " + resumo);
            }
        }
    }

    @Test
    @DisplayName("o tipo do provedor muda a frase inteira, não um pedaço concatenado")
    void tipoTrocaAFraseInteira() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);

        assertEquals("Cloudflare detected (WAF) via an exclusive header. Protection layer active.",
                servico().buildSummary(resultado(true, "WAF", "HIGH")));
        assertEquals("Cloudflare detected (CDN, no native WAF) via an exclusive header. "
                        + "Delivery CDN — it does not grant WAF protection by default.",
                servico().buildSummary(resultado(true, "CDN", "HIGH")));

        LocaleContextHolder.setLocale(Locale.forLanguageTag("pt-BR"));
        assertEquals("Cloudflare detectado (CDN com WAF opcional) via header exclusivo. "
                        + "Camada de proteção ativa.",
                servico().buildSummary(resultado(true, "BOTH", "HIGH")));
    }

    // ── Evidência ────────────────────────────────────────────────────────────

    @Test
    @DisplayName("os códigos HTTP atravessam a evidência sem formatação de número")
    void codigosHttpNaEvidencia() {
        var catalog = new MessageCatalog(fonte());

        LocaleContextHolder.setLocale(Locale.ENGLISH);
        assertEquals("Malicious payload blocked (HTTP 403) while benign requests "
                        + "went through (HTTP 200/200)",
                catalog.evidence("WAF_PAYLOAD_BLOCKED", 403, 200, 200));

        LocaleContextHolder.setLocale(Locale.forLanguageTag("pt-BR"));
        assertEquals("Payload malicioso bloqueado (HTTP 403) enquanto requisições "
                        + "benignas passaram (HTTP 200/200)",
                catalog.evidence("WAF_PAYLOAD_BLOCKED", 403, 200, 200));
    }

    private static ResourceBundleMessageSource fonte() {
        var source = new ResourceBundleMessageSource();
        source.setBasename("messages");
        source.setDefaultEncoding("UTF-8");
        source.setFallbackToSystemLocale(false);
        return source;
    }
}
