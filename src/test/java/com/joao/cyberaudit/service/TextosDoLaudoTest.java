package com.joao.cyberaudit.service;

import com.joao.cyberaudit.config.LocaleConfig;
import com.joao.cyberaudit.model.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.ResourceBundleMessageSource;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * BUG-15: textos do laudo errados sem mudar a nota — o "null" no bônus de WAF, a porta 80
 * LOW quando só redireciona, módulos montados no idioma do servidor e o HSTS max-age=0 em
 * inglês fixo. Tudo saiu de um laudo de cliente.
 */
class TextosDoLaudoTest {

    private static MessageCatalog catalogoReal() {
        var fonte = new ResourceBundleMessageSource();
        fonte.setBasename("messages");
        fonte.setDefaultEncoding("UTF-8");
        fonte.setFallbackToSystemLocale(false);
        return new MessageCatalog(fonte);
    }

    private final MessageCatalog catalog = catalogoReal();

    @AfterEach
    void limpaIdioma() {
        LocaleContextHolder.resetLocaleContext();
    }

    /** WAF achado só porque bloqueou o payload: sem header que diga qual é. */
    private static WafDetectionResult wafSemProvedor() {
        return WafDetectionResult.builder().detected(true).provider(null)
                .category("WAF").confidence("MEDIUM").probeResponse("BLOCKED").build();
    }

    @Nested
    @DisplayName("WAF sem provedor identificado")
    class Waf {

        private String notaDoWaf() {
            SSLInfo    ssl = new SSLInfo(true, true, "2030-01-01", 300, "Certificado válido", 365);
            TlsDetails tls = new TlsDetails("TLSv1.3", "TLS_AES_256_GCM_SHA384", false, "OK");
            ScoreResult r = new ScoreService(catalog).calculate(
                    ssl, tls, Map.of(), true,
                    false, false, false, false, false, List.of(),
                    null, List.of(), List.of(), false,
                    List.of(), List.of(), true,
                    List.of(), List.of(), null, wafSemProvedor(),
                    List.of(), List.of(), List.of(), List.of(),
                    List.of(), List.of(), List.of(), List.of(), List.of());
            return r.getNotes().stream().filter(n -> n.contains("+")).findFirst().orElseThrow();
        }

        @Test
        @DisplayName("a nota do bônus não diz \"null\" (o laudo trazia \"WAF detectado (null, probe bloqueado)\")")
        void notaDoBonus() {
            LocaleContextHolder.setLocale(LocaleConfig.PADRAO);
            assertEquals("WAF detectado (provedor não identificado, probe bloqueado): +5", notaDoWaf());

            LocaleContextHolder.setLocale(Locale.ENGLISH);
            assertEquals("WAF detected (unidentified provider, probe blocked): +5", notaDoWaf());
        }

        @Test
        @DisplayName("a mudança entre scans também não diz \"null\"")
        void mudancaEntreScans() {
            LocaleContextHolder.setLocale(LocaleConfig.PADRAO);
            ScanResult antes  = ScanResult.builder().build();
            ScanResult depois = ScanResult.builder().wafDetectionResult(wafSemProvedor()).build();

            String descricao = new ScanChangeDetector(catalog).detect(depois, antes).stream()
                    .filter(c -> "WAF".equals(c.getCategory())).findFirst().orElseThrow()
                    .getDescription();

            assertFalse(descricao.contains("null"), descricao);
            assertTrue(descricao.endsWith("provedor não identificado"), descricao);
        }
    }

    @Nested
    @DisplayName("Porta 80 que só redireciona para HTTPS")
    class Porta80 {

        private final PortScanService portas = new PortScanService(null, catalog);

        private static PortScanService.RespostaHttp ler(String... linhas) throws IOException {
            return PortScanService.lerResposta(new BufferedReader(new StringReader(
                    String.join("\r\n", linhas) + "\r\n\r\n")));
        }

        @Test
        void redirectParaHttps() throws IOException {
            var r = ler("HTTP/1.1 301 Moved Permanently", "server: hcdn",
                    "location: https://www.exemplo.com.br/");
            assertTrue(r.redirecionaParaHttps());
            assertTrue(r.evidencia().contains("Location: https://www.exemplo.com.br/"), r.evidencia());
        }

        @Test
        void todosOsStatusDeRedirect() throws IOException {
            for (String s : List.of("301 Moved Permanently", "302 Found", "303 See Other",
                    "307 Temporary Redirect", "308 Permanent Redirect")) {
                assertTrue(ler("HTTP/1.1 " + s, "Location: https://alvo/").redirecionaParaHttps(), s);
            }
        }

        @Test
        @DisplayName("servir conteúdo, redirecionar para http:// ou para caminho relativo não é \"só redireciona\"")
        void naoEhRedirectParaHttps() throws IOException {
            assertFalse(ler("HTTP/1.1 200 OK", "Server: nginx").redirecionaParaHttps());
            assertFalse(ler("HTTP/1.1 301 Moved Permanently", "Location: http://alvo/home").redirecionaParaHttps());
            assertFalse(ler("HTTP/1.1 302 Found", "Location: /login").redirecionaParaHttps());
            assertFalse(ler("HTTP/1.1 200 OK", "Location: https://alvo/").redirecionaParaHttps(),
                    "Location sem status de redirect não redireciona");
        }

        @Test
        @DisplayName("redirect vira INFO, com texto de porta que faz o que deve")
        void achadoInfo() throws IOException {
            LocaleContextHolder.setLocale(LocaleConfig.PADRAO);
            PortFinding f = portas.achadoHttp(PortScanService.configDaPorta(80), 67,
                    ler("HTTP/1.1 301 Moved Permanently", "Location: https://alvo/"));

            assertEquals("INFO", f.getSeverity());
            assertEquals(catalog.impact("PORT_80_REDIRECT"), f.getImpact());
            assertEquals(catalog.recommendation("PORT_80_REDIRECT"), f.getRecommendation());
            assertFalse(f.getImpact().contains("HTTP exposto"), f.getImpact());
        }

        @Test
        @DisplayName("porta 80 que serve conteúdo continua LOW, com o texto de antes")
        void servindoConteudoContinuaLow() throws IOException {
            LocaleContextHolder.setLocale(LocaleConfig.PADRAO);
            PortFinding f = portas.achadoHttp(PortScanService.configDaPorta(80), 67,
                    ler("HTTP/1.1 200 OK", "Server: Apache"));

            assertEquals("LOW", f.getSeverity());
            assertEquals(catalog.impact("PORT_80"), f.getImpact());
        }
    }

    @Nested
    @DisplayName("HSTS max-age=0")
    class HstsZero {

        @Test
        @DisplayName("o motivo sai do catálogo — era \"max-age=0 deletes HSTS\" chumbado")
        void noIdiomaDoLaudo() {
            HeaderService hs = new HeaderService(catalog);
            Map<String, String> h = new LinkedHashMap<>();
            h.put("strict-transport-security", "max-age=0");

            LocaleContextHolder.setLocale(LocaleConfig.PADRAO);
            assertEquals("WEAK (max-age=0 apaga o HSTS)",
                    hs.analyzeSecurityHeaders(h).get("Strict-Transport-Security"));

            LocaleContextHolder.setLocale(Locale.ENGLISH);
            assertEquals("WEAK (max-age=0 deletes HSTS)",
                    hs.analyzeSecurityHeaders(h).get("Strict-Transport-Security"));
        }
    }

    /**
     * Thread de pool nasce sem idioma e cai no do servidor (ver IdiomaThreads). Os hosts
     * relacionados saíram em inglês num laudo em português ("max-age far too short:
     * 86,400s"), e os achados de takeover sairiam igual. A regra é estrutural, então o
     * teste também: todo pool do código principal nasce com a fábrica de idioma.
     */
    @Nested
    @DisplayName("Pools com idioma")
    class Pools {

        private static final Pattern POOL = Pattern.compile("Executors\\.new\\w+\\(");
        private static final Pattern COMENTARIO = Pattern.compile("(?s)/\\*.*?\\*/|//[^\\n]*");

        @Test
        @DisplayName("todo Executors.new… do código principal usa IdiomaThreads.fabrica")
        void todoPoolCarregaOIdioma() throws IOException {
            List<String> semIdioma = new ArrayList<>();
            try (Stream<Path> arquivos = Files.walk(Path.of("src/main/java"))) {
                for (Path p : arquivos.filter(a -> a.toString().endsWith(".java")).toList()) {
                    String codigo = COMENTARIO.matcher(Files.readString(p)).replaceAll("");
                    Matcher m = POOL.matcher(codigo);
                    while (m.find()) {
                        int fim = codigo.indexOf(';', m.start());
                        String chamada = codigo.substring(m.start(), fim < 0 ? codigo.length() : fim);
                        if (!chamada.contains("IdiomaThreads.fabrica(")) {
                            semIdioma.add(p.getFileName() + ": " + chamada.replaceAll("\\s+", " "));
                        }
                    }
                }
            }
            assertTrue(semIdioma.isEmpty(), "pool sem idioma: " + semIdioma);
        }
    }
}
