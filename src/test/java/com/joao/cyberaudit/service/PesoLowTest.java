package com.joao.cyberaudit.service;

import com.joao.cyberaudit.config.LocaleConfig;
import com.joao.cyberaudit.model.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.ResourceBundleMessageSource;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * BUG-14: achado LOW custava o mesmo que achado MEDIUM.
 *
 * Versão exposta, robots.txt e Referrer-Policy ausente (todos LOW) tiravam 5 — o mesmo que
 * X-Frame-Options ausente ou HSTS fraco (MEDIUM). Num laudo de cliente, três itens de
 * higiene somavam -13, mais que o cookie de sessão sem HttpOnly. A severidade já separava
 * "risco explorável" de "higiene"; o peso é que não acompanhava.
 *
 * Escada: nenhum LOW custa mais que 2. Custa 2 o LOW que entrega informação ao atacante
 * (versão para buscar CVE, mapa do robots.txt, método TRACE, UI de documentação de API);
 * custa 1 o LOW que é só boa prática ausente (security.txt, Permissions-Policy, WAF e
 * Referrer-Policy — sem header, o navegador atual já aplica strict-origin-when-cross-origin).
 * MEDIUM e HIGH não mudam nesta etapa.
 */
class PesoLowTest {

    private final ScoreService scoreService = new ScoreService(catalogoReal());

    private static MessageCatalog catalogoReal() {
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

    /** Alvo sem nenhum achado. Cada caso troca só o que testa. */
    static final class Alvo {
        final Map<String, String> headers = new LinkedHashMap<>(Map.of(
                "Strict-Transport-Security", "OK (max-age=31536000; includeSubDomains)",
                "Content-Security-Policy",   "OK",
                "X-Frame-Options",           "OK (DENY)",
                "X-Content-Type-Options",    "OK (nosniff)",
                "Referrer-Policy",           "OK (no-referrer)",
                "Permissions-Policy",        "OK (camera=())"));
        List<CookieFinding>          cookies     = new ArrayList<>();
        List<String>                 robots      = new ArrayList<>();
        boolean                      versao      = false;
        List<HttpMethodFinding>      metodos     = new ArrayList<>();
        Boolean                      securityTxt = true;
        DnsSecurityResult            dns         = null;
        WafDetectionResult           waf         = null;
        List<ApiDocsExposureFinding> apiDocs     = new ArrayList<>();
    }

    private ScoreResult score(Alvo a) {
        SSLInfo    ssl = new SSLInfo(true, true, "2030-01-01", 300, "Certificado válido", 365);
        TlsDetails tls = new TlsDetails("TLSv1.3", "TLS_AES_256_GCM_SHA384", false, "OK");
        return scoreService.calculate(
                ssl, tls, a.headers, true,
                false, false, false, false, false, List.of(),
                null, a.cookies, a.robots, a.versao,
                List.of(), a.metodos, a.securityTxt,
                List.of(), List.of(), a.dns, a.waf,
                List.of(), a.apiDocs, List.of(), List.of(),
                List.of(), List.of(), List.of(), List.of(), List.of());
    }

    private ScoreResult score(Consumer<Alvo> ajuste) {
        Alvo a = new Alvo();
        ajuste.accept(a);
        return score(a);
    }

    private static WafDetectionResult semWaf() {
        return WafDetectionResult.builder().detected(false).build();
    }

    /** WAF real, probe bloqueado, confiança média: o +5 que aparece no laudo. */
    private static WafDetectionResult wafComProbeBloqueado() {
        return WafDetectionResult.builder().detected(true).provider("Cloudflare")
                .category("WAF").confidence("MEDIUM").probeResponse("BLOCKED").build();
    }

    private static HttpMethodFinding metodo(String nome, String severidade) {
        return new HttpMethodFinding(nome, 200, true, severidade, "risco descrito pelo serviço");
    }

    /** Severidade do serviço: HIGH = spec JSON/YAML (achado MEDIUM), MEDIUM = UI (achado LOW). */
    private static ApiDocsExposureFinding apiDoc(String path, String tipo, String severidade) {
        return ApiDocsExposureFinding.builder().path(path).type(tipo).severity(severidade)
                .description("documentação exposta").build();
    }

    private static DnsSecurityResult spoofing(String risco) {
        return DnsSecurityResult.builder().emailSpoofingRisk(risco).summary("resumo do DNS").build();
    }

    /** As notas que descontam ("…: -N"). SSL_OK e afins não trazem número. */
    private static List<String> notasComDesconto(ScoreResult r) {
        return r.getNotes().stream().filter(n -> n.matches(".*-\\d+$")).toList();
    }

    private static SecurityIssue issue(ScoreResult r, String id) {
        return r.getIssues().stream().filter(i -> i.getId().equals(id)).findFirst()
                .orElseThrow(() -> new AssertionError("sem issue " + id + " em " + r.getIssues()));
    }

    static Stream<Arguments> itensLow() {
        return Stream.of(
                Arguments.of("versão exposta", (Consumer<Alvo>) a -> a.versao = true,
                        "SERVER_VERSION_EXPOSED", 2),
                Arguments.of("robots.txt", (Consumer<Alvo>) a -> a.robots.add("/admin/"),
                        "SENSITIVE_ROBOTS_PATHS", 2),
                Arguments.of("TRACE habilitado", (Consumer<Alvo>) a -> a.metodos.add(metodo("TRACE", "LOW")),
                        "DANGEROUS_HTTP_METHOD", 2),
                Arguments.of("UI de docs de API", (Consumer<Alvo>) a -> a.apiDocs.add(apiDoc("/swagger-ui/", "SWAGGER_UI", "MEDIUM")),
                        "API_DOCS_SWAGGER_UI", 2),
                Arguments.of("Referrer-Policy ausente", (Consumer<Alvo>) a -> a.headers.put("Referrer-Policy", "MISSING"),
                        "REFERRER_POLICY_MISSING", 1),
                Arguments.of("Permissions-Policy ausente", (Consumer<Alvo>) a -> a.headers.put("Permissions-Policy", "MISSING"),
                        "PERMISSIONS_POLICY_MISSING", 1),
                Arguments.of("security.txt ausente", (Consumer<Alvo>) a -> a.securityTxt = false,
                        "SECURITY_TXT_MISSING", 1),
                Arguments.of("sem WAF", (Consumer<Alvo>) a -> a.waf = semWaf(),
                        "NO_WAF_DETECTED", 1));
    }

    @Nested
    @DisplayName("Cada LOW custa no máximo 2")
    class Escada {

        @ParameterizedTest(name = "{0} custa {3}")
        @MethodSource("com.joao.cyberaudit.service.PesoLowTest#itensLow")
        void custo(String nome, Consumer<Alvo> ajuste, String id, int custo) {
            ScoreResult r = score(ajuste);

            assertEquals(100 - custo, r.getScore(), nome);
            assertEquals("LOW", issue(r, id).getSeverity(), nome + ": continua LOW");
            assertEquals(RiskLevel.SECURE, r.getRiskLevel());
        }

        /** O número escrito na nota é o que o código desconta — nos dois idiomas. */
        @ParameterizedTest(name = "nota de {0} diz -{3}")
        @MethodSource("com.joao.cyberaudit.service.PesoLowTest#itensLow")
        void notaDizOCusto(String nome, Consumer<Alvo> ajuste, String id, int custo) {
            for (Locale idioma : new Locale[] { LocaleConfig.PADRAO, Locale.ENGLISH }) {
                LocaleContextHolder.setLocale(idioma);
                List<String> notas = notasComDesconto(score(ajuste));

                assertEquals(1, notas.size(), idioma + ": " + notas);
                assertTrue(notas.get(0).endsWith(": -" + custo),
                        idioma + " — " + nome + ": " + notas.get(0));
            }
        }
    }

    @Nested
    @DisplayName("O que não é LOW não muda")
    class Inalterados {

        @Test
        @DisplayName("spec de API (achado MEDIUM) segue -3; com a UI junto, -5; teto -8")
        void apiDocs() {
            assertEquals(97, score(a -> a.apiDocs.add(apiDoc("/v3/api-docs", "OPENAPI", "HIGH"))).getScore());
            assertEquals(95, score(a -> {
                a.apiDocs.add(apiDoc("/v3/api-docs", "OPENAPI", "HIGH"));
                a.apiDocs.add(apiDoc("/swagger-ui/", "SWAGGER_UI", "MEDIUM"));
            }).getScore());
            assertEquals(92, score(a -> {
                for (String p : List.of("/v2/api-docs", "/v3/api-docs", "/openapi.json", "/swagger.json"))
                    a.apiDocs.add(apiDoc(p, "OPENAPI", "HIGH"));
            }).getScore());
        }

        @Test
        @DisplayName("método HTTP MEDIUM segue -8 e HIGH -15")
        void metodosMediumEHigh() {
            assertEquals(92, score(a -> a.metodos.add(metodo("PATCH", "MEDIUM"))).getScore());
            assertEquals(85, score(a -> a.metodos.add(metodo("PUT", "HIGH"))).getScore());
        }

        @Test
        @DisplayName("Referrer-Policy insegura (MEDIUM) segue -5: troca o padrão seguro por um pior")
        void referrerFraco() {
            ScoreResult r = score(a -> a.headers.put("Referrer-Policy", "WEAK (unsafe-url)"));
            assertEquals(95, r.getScore());
            assertEquals("MEDIUM", issue(r, "REFERRER_POLICY_WEAK").getSeverity());
        }
    }

    @Nested
    @DisplayName("Laudos de um site de cliente, refeitos com as etapas A–F")
    class Laudos {

        /**
         * Depois da correção do cliente: HSTS fraco, robots.txt, sem security.txt, DMARC em
         * quarantine (LOW desde o BUG-10), WAF com probe bloqueado. Saiu 86; com C, 92.
         */
        @Test
        void depoisDaCorrecao() {
            ScoreResult r = score(a -> {
                a.headers.put("Strict-Transport-Security", "WEAK (max-age=86400)");
                a.robots.add("/admin/");
                a.securityTxt = false;
                a.dns = spoofing("LOW");
                a.waf = wafComProbeBloqueado();
            });

            assertEquals(100 - 5 - 2 - 1 + 5, r.getScore());   // 97
            assertEquals(RiskLevel.SECURE, r.getRiskLevel());
        }

        /**
         * Primeiro laudo: HSTS ausente, versão exposta, sessão PHP sem HttpOnly, robots.txt,
         * sem security.txt, DMARC p=none, WAF. Saiu 60 (com o CVE falso do BUG-08).
         * O cookie de sessão HIGH segura o risco em MEDIUM (BUG-12).
         */
        @Test
        void primeiroLaudo() {
            ScoreResult r = score(a -> {
                a.headers.put("Strict-Transport-Security", "MISSING");
                a.versao = true;
                a.cookies.add(new CookieFinding("PHPSESSID", false, true, "MISSING", "HIGH", "sem HttpOnly"));
                a.cookies.add(new CookieFinding("visitante", false, false, "MISSING", "LOW", "sem flags"));
                a.robots.add("/admin/");
                a.securityTxt = false;
                a.dns = spoofing("MEDIUM");
                a.waf = wafComProbeBloqueado();
            });

            assertEquals(100 - 10 - 2 - 10 - 2 - 1 - 6 + 5, r.getScore());   // 74
            assertEquals(RiskLevel.MEDIUM, r.getRiskLevel());
        }
    }
}
