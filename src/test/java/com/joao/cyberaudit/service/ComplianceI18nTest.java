package com.joao.cyberaudit.service;

import com.joao.cyberaudit.config.LocaleConfig;
import com.joao.cyberaudit.dto.ComplianceReport;
import com.joao.cyberaudit.dto.ComplianceReport.ComplianceItem;
import com.joao.cyberaudit.model.CorsResult;
import com.joao.cyberaudit.model.DnsSecurityResult;
import com.joao.cyberaudit.model.PathTraversalFinding;
import com.joao.cyberaudit.model.SSLInfo;
import com.joao.cyberaudit.model.ScanResult;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.ResourceBundleMessageSource;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * O módulo de conformidade segue o idioma do laudo.
 *
 * Era o maior bolsão de português chumbado que sobrava: título do controle,
 * citação da norma, recomendação e cada não-conformidade nasciam literais no
 * {@link ComplianceMappingService}. É também o módulo que produz mais texto
 * corrido — um cliente lendo a tela em inglês recebia o relatório LGPD/ISO
 * inteiro em português, e era exatamente o relatório que ele tinha comprado.
 */
class ComplianceI18nTest {

    private ComplianceMappingService servico() {
        var fonte = new ResourceBundleMessageSource();
        fonte.setBasename("messages");
        fonte.setDefaultEncoding("UTF-8");
        fonte.setFallbackToSystemLocale(false);
        return new ComplianceMappingService(new MessageCatalog(fonte));
    }

    @AfterEach
    void limpaIdioma() {
        LocaleContextHolder.resetLocaleContext();
    }

    /** Um resultado que falha em tudo o que o mapeamento sabe olhar. */
    private ScanResult resultadoRuim() {
        return ScanResult.builder()
                .sslInfo(new SSLInfo(true, false, null, 0, "x"))
                .redirectsToHttps(false)
                .headers(Map.of())                       // nenhum header de segurança
                .serverVersionExposed(true)
                .dbErrorLeakageSuspected(true)
                .reflectedXssSuspected(true)
                .securityTxtPresent(false)
                .corsResult(new CorsResult(true, "*", true, false, true, false, "x"))
                .dnsSecurityResult(DnsSecurityResult.builder()
                        .spfPresent(false).dmarcPresent(false).caaPresent(false).build())
                .build();
    }

    private Stream<ComplianceItem> itens(ComplianceReport r) {
        return Stream.concat(r.getLgpdItems().stream(), r.getIsoItems().stream());
    }

    private Stream<String> todoOTexto(ComplianceReport r) {
        return itens(r).flatMap(i -> Stream.concat(
                Stream.of(i.getTitle(), i.getRequirement(), i.getRecommendation()),
                i.getFindings().stream()));
    }

    @Test
    @DisplayName("nenhum texto sai como chave crua — toda chave existe nos dois idiomas")
    void semChaveCrua() {
        for (Locale idioma : List.of(LocaleConfig.PADRAO, Locale.ENGLISH)) {
            LocaleContextHolder.setLocale(idioma);
            ComplianceReport r = servico().generate(resultadoRuim());

            List<String> cruas = todoOTexto(r)
                    .filter(t -> t != null && t.startsWith("compliance."))
                    .toList();

            assertTrue(cruas.isEmpty(), idioma + " sem tradução para: " + cruas);
        }
    }

    @Test
    @DisplayName("em inglês, nada de acento do português no relatório")
    void inglesEhIngles() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        ComplianceReport r = servico().generate(resultadoRuim());

        List<String> comAcento = todoOTexto(r)
                .filter(t -> t != null && t.matches(".*[áàâãéèêíóôõúüç].*"))
                .toList();

        assertTrue(comAcento.isEmpty(), "português vazou para o relatório em inglês: " + comAcento);
    }

    @Test
    @DisplayName("os mesmos itens saem nos dois idiomas, com texto diferente")
    void traducaoNaoEhCopia() {
        LocaleContextHolder.setLocale(LocaleConfig.PADRAO);
        ComplianceReport pt = servico().generate(resultadoRuim());
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        ComplianceReport en = servico().generate(resultadoRuim());

        // A referência do controle é citação de norma: tem de ser IGUAL nos dois.
        assertEquals(itens(pt).map(ComplianceItem::getReference).toList(),
                itens(en).map(ComplianceItem::getReference).toList());
        // O score e a contagem não podem mudar com o idioma.
        assertEquals(pt.getOverallScore(), en.getOverallScore());
        assertEquals(pt.getLgpdFailed(), en.getLgpdFailed());
        assertEquals(pt.getIsoFailed(), en.getIsoFailed());

        // E o texto tem de mudar — senão é cópia disfarçada de tradução.
        assertFalse(itens(pt).map(ComplianceItem::getTitle).toList()
                        .equals(itens(en).map(ComplianceItem::getTitle).toList()),
                "os títulos saíram idênticos: a tradução não aconteceu");
    }

    @Test
    @DisplayName("a não-conformidade com parâmetro não perde o dado na tradução")
    void parametroSobrevive() {
        ScanResult r = ScanResult.builder()
                .headers(Map.of("Strict-Transport-Security", "max-age=63072000",
                        "Content-Security-Policy", "default-src 'self'",
                        "X-Frame-Options", "DENY"))
                .redirectsToHttps(true)
                .pathTraversal(List.of(
                        PathTraversalFinding.builder().parameter("file").build(),
                        PathTraversalFinding.builder().parameter("path").build()))
                .build();

        for (Locale idioma : List.of(LocaleConfig.PADRAO, Locale.ENGLISH)) {
            LocaleContextHolder.setLocale(idioma);
            List<String> achados = servico().generate(r).getLgpdItems().stream()
                    .filter(i -> "Art. 49".equals(i.getReference()))
                    .flatMap(i -> i.getFindings().stream())
                    .toList();

            assertTrue(achados.stream().anyMatch(a -> a.contains("2")),
                    idioma + " engoliu a contagem de parâmetros: " + achados);
        }
    }

    @Test
    @DisplayName("controle sem achado passa, e o texto do requisito continua vindo traduzido")
    void itemQuePassaTambemTemTexto() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        ComplianceReport r = servico().generate(ScanResult.builder()
                .headers(Map.of("Strict-Transport-Security", "max-age=63072000",
                        "Content-Security-Policy", "default-src 'self'",
                        "X-Frame-Options", "DENY"))
                .redirectsToHttps(true)
                .build());

        ComplianceItem art46 = r.getLgpdItems().stream()
                .filter(i -> "Art. 46".equals(i.getReference()))
                .findFirst().orElseThrow();

        assertEquals("PASS", art46.getStatus());
        assertEquals("Security in data processing", art46.getTitle());
        assertFalse(art46.getRequirement().isBlank());
    }
}
