package com.joao.cyberaudit.service;

import com.joao.cyberaudit.config.LocaleConfig;
import com.joao.cyberaudit.model.CookieFinding;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

/**
 * O texto dos módulos que ainda nascia literal em português.
 *
 * Cada um destes serviços montava frase no código: o veredito do CORS (que sai no
 * card e como "Assessment" no PDF, monolíngue em inglês), os problemas listados
 * dentro do card de cada cookie, a mensagem do certificado que a API devolve no
 * resultado, o impacto e a recomendação de cada porta aberta, e a prosa entre
 * parênteses dos cabeçalhos de segurança.
 *
 * O prefixo {@code OK}/{@code MISSING}/{@code WEAK} do cabeçalho fica FORA do
 * catálogo de propósito — é ele que o Frontend lê para escolher ícone e cor
 * ({@code val.startsWith("OK")}), então traduzi-lo quebraria a tela em inglês em
 * vez de melhorá-la. {@link #prefixoDoHeaderNaoEhTraduzido()} guarda isso.
 */
class ModuloTextoI18nTest {

    private static MessageCatalog catalogo() {
        var fonte = new ResourceBundleMessageSource();
        fonte.setBasename("messages");
        fonte.setDefaultEncoding("UTF-8");
        fonte.setFallbackToSystemLocale(false);
        return new MessageCatalog(fonte);
    }

    @AfterEach
    void limpaIdioma() {
        LocaleContextHolder.resetLocaleContext();
    }

    // ── Chaves presentes nos dois arquivos ───────────────────────────────────

    private static final List<String> CHAVES = List.of(
            "desc.CORS_REFLECTION_CREDENTIALS", "desc.CORS_REFLECTION",
            "desc.CORS_WILDCARD_CREDENTIALS", "desc.CORS_NULL_ORIGIN",
            "desc.CORS_AUSENTE", "desc.CORS_ORIGEM_ESPECIFICA", "desc.CORS_PROBE_FALHOU",
            "evidence.COOKIE_SEM_SECURE", "evidence.COOKIE_SEM_HTTPONLY",
            "evidence.COOKIE_SEM_SAMESITE", "evidence.COOKIE_SAMESITE_NONE_SEM_SECURE",
            "desc.SSL_URL_VAZIA", "desc.SSL_SEM_HTTPS", "desc.SSL_CERT_VALIDO",
            "desc.SSL_CERT_EXPIRADO", "desc.SSL_ERRO_VERIFICACAO",
            "valor.hstsSemMaxAge", "valor.hstsMaxAgeCurto", "valor.cspUnsafe",
            "evidence.PORT_BANNER_MSSQL", "evidence.PORT_BANNER_ORACLE",
            "evidence.PORT_BANNER_MYSQL", "evidence.PORT_BANNER_POSTGRES",
            "evidence.PORT_BANNER_REDIS", "evidence.PORT_BANNER_ELASTIC",
            "evidence.PORT_CONNECTED_VIA",
            "evidence.DNS_SPF_DUPLICADO", "evidence.DNS_DMARC_DUPLICADO",
            "desc.DNS_SPOOFING_CRITICAL", "desc.DNS_SPOOFING_HIGH",
            "desc.DNS_SPOOFING_MEDIUM", "desc.DNS_SPOOFING_LOW",
            "desc.DNS_SPOOFING_UNKNOWN", "desc.DNS_SPOOFING_INDEFINIDO");

    @Test
    @DisplayName("toda chave nova existe, e não vazia, nos dois arquivos")
    void catalogoCompleto() {
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
            // Sigla e nome próprio seriam exceção legítima; nenhuma destas é.
            assertFalse(pt.getString(chave).equals(en.getString(chave)),
                    chave + " saiu idêntica nos dois idiomas");
        }
    }

    // ── CORS ─────────────────────────────────────────────────────────────────

    private String vereditoCors(boolean wildcard, boolean reflects, boolean credentials,
                                boolean nullAccepted, String acao) {
        var servico = new CorsAnalyzerService(mock(HttpFetchService.class), catalogo());
        return (String) ReflectionTestUtils.invokeMethod(servico, "buildMessage",
                wildcard, reflects, credentials, nullAccepted, acao);
    }

    @Test
    @DisplayName("o veredito do CORS sai no idioma do laudo")
    void corsSegueOIdioma() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        assertEquals("CORS reflects the request Origin — any site can reach your resources",
                vereditoCors(false, true, false, false, "https://evil.example"));
        assertEquals("No CORS headers — the safe default (same-origin only)",
                vereditoCors(false, false, false, false, "NOT_SET"));
        assertEquals("CORS restricted to a specific origin: https://app.example",
                vereditoCors(false, false, false, false, "https://app.example"));

        LocaleContextHolder.setLocale(LocaleConfig.PADRAO);
        assertEquals("CORS reflete a Origin do request — qualquer site acessa seus recursos",
                vereditoCors(false, true, false, false, "https://evil.example"));
    }

    // ── Cookies ──────────────────────────────────────────────────────────────

    private CookieFinding cookie(String raw) {
        return new CookieSecurityService(catalogo()).analyze(List.of(raw)).get(0);
    }

    @Test
    @DisplayName("os problemas do cookie saem no idioma do laudo")
    void cookiesSeguemOIdioma() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        String en = cookie("SESSIONID=abc; Path=/").getIssues();
        assertTrue(en.contains("no Secure"), en);
        assertTrue(en.contains("no HttpOnly"), en);
        assertTrue(en.contains("no SameSite"), en);

        LocaleContextHolder.setLocale(LocaleConfig.PADRAO);
        String pt = cookie("SESSIONID=abc; Path=/").getIssues();
        assertTrue(pt.contains("sem Secure"), pt);
        assertTrue(pt.contains("sem HttpOnly"), pt);

        // O risco é classificação, não texto: não pode mudar com o idioma.
        assertEquals("HIGH", cookie("SESSIONID=abc; Path=/").getRisk());
    }

    // ── Certificado ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("a mensagem do certificado sai no idioma do laudo")
    void sslSegueOIdioma() {
        var servico = new SSLService(catalogo());

        LocaleContextHolder.setLocale(Locale.ENGLISH);
        assertEquals("Site does not use HTTPS", servico.checkSSL("http://exemplo.com").getMessage());
        assertEquals("Empty URL", servico.checkSSL("  ").getMessage());

        LocaleContextHolder.setLocale(LocaleConfig.PADRAO);
        assertEquals("Site não usa HTTPS", servico.checkSSL("http://exemplo.com").getMessage());
    }

    // ── Headers ──────────────────────────────────────────────────────────────

    private Map<String, String> analisa(Map<String, String> headers) {
        return new HeaderService(catalogo()).analyzeSecurityHeaders(new HashMap<>(headers));
    }

    @Test
    @DisplayName("a prosa do cabeçalho fraco sai no idioma do laudo")
    void headersSeguemOIdioma() {
        Map<String, String> fracos = Map.of(
                "strict-transport-security", "max-age=60",
                "content-security-policy", "script-src 'self' 'unsafe-inline'");

        LocaleContextHolder.setLocale(Locale.ENGLISH);
        Map<String, String> en = analisa(fracos);
        assertEquals("WEAK (max-age far too short: 60s)", en.get("Strict-Transport-Security"));
        assertEquals("WEAK (unsafe-inline in script-src, or unsafe-eval)",
                en.get("Content-Security-Policy"));

        LocaleContextHolder.setLocale(LocaleConfig.PADRAO);
        Map<String, String> pt = analisa(fracos);
        assertEquals("WEAK (max-age muito curto: 60s)", pt.get("Strict-Transport-Security"));
        assertEquals("WEAK (unsafe-inline em script-src ou unsafe-eval)",
                pt.get("Content-Security-Policy"));
    }

    @Test
    @DisplayName("o prefixo OK/MISSING/WEAK do cabeçalho NÃO é traduzido")
    void prefixoDoHeaderNaoEhTraduzido() {
        // O Frontend escolhe ícone e cor por val.startsWith("OK") / ("MISSING").
        // Traduzir o prefixo deixaria todo cabeçalho em inglês com cara de WEAK.
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        Map<String, String> en = analisa(Map.of("x-frame-options", "DENY"));
        assertEquals("OK (DENY)", en.get("X-Frame-Options"));
        assertEquals("MISSING", en.get("Content-Security-Policy"));

        LocaleContextHolder.setLocale(LocaleConfig.PADRAO);
        Map<String, String> pt = analisa(Map.of("x-frame-options", "DENY"));
        assertEquals("OK (DENY)", pt.get("X-Frame-Options"));
        assertEquals("MISSING", pt.get("Content-Security-Policy"));
    }

    // ── Portas ───────────────────────────────────────────────────────────────

    private String impactoDaPorta(int porta, String servico) {
        var scanner = new PortScanService(mock(HostingProviderPolicy.class), catalogo());
        return (String) ReflectionTestUtils.invokeMethod(scanner, "impactFor", porta, servico);
    }

    private String recomendacaoDaPorta(int porta) {
        var scanner = new PortScanService(mock(HostingProviderPolicy.class), catalogo());
        return (String) ReflectionTestUtils.invokeMethod(scanner, "recommendationFor", porta);
    }

    @Test
    @DisplayName("toda porta conhecida tem impacto e recomendação nos dois idiomas")
    void todaPortaTemTexto() {
        List<Integer> portas = List.of(21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587,
                993, 995, 1433, 1521, 3306, 5432, 6379, 8080, 8443, 9200);

        for (Locale idioma : List.of(LocaleConfig.PADRAO, Locale.ENGLISH)) {
            LocaleContextHolder.setLocale(idioma);
            for (int porta : portas) {
                String impacto = impactoDaPorta(porta, "Serviço " + porta);
                String recomendacao = recomendacaoDaPorta(porta);
                assertFalse(impacto.startsWith("issue."),
                        idioma + " sem impacto para a porta " + porta + ": " + impacto);
                assertFalse(recomendacao.startsWith("issue."),
                        idioma + " sem recomendação para a porta " + porta + ": " + recomendacao);
            }
        }
    }

    @Test
    @DisplayName("porta desconhecida cai no texto genérico, com o nome do serviço dentro")
    void portaDesconhecida() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        assertEquals("Exposing the Gopher service may widen the attack surface.",
                impactoDaPorta(70, "Gopher"));

        LocaleContextHolder.setLocale(LocaleConfig.PADRAO);
        assertEquals("Serviço Gopher exposto pode ampliar a superfície de ataque.",
                impactoDaPorta(70, "Gopher"));
    }

    @Test
    @DisplayName("em inglês, nenhum texto de porta carrega acento do português")
    void portasEmInglesSaoIngles() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        for (int porta : List.of(21, 22, 23, 25, 53, 80, 443, 1433, 1521, 3306, 5432, 6379, 9200)) {
            assertFalse(impactoDaPorta(porta, "x").matches(".*[áàâãéèêíóôõúüç].*"),
                    "porta " + porta + ": " + impactoDaPorta(porta, "x"));
            assertFalse(recomendacaoDaPorta(porta).matches(".*[áàâãéèêíóôõúüç].*"),
                    "porta " + porta + ": " + recomendacaoDaPorta(porta));
        }
    }
}
