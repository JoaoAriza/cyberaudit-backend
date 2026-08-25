package com.joao.cyberaudit.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.support.ResourceBundleMessageSource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * O catálogo de texto dos achados.
 *
 * O texto saiu do código e foi para messages.properties. Isso cria um risco novo
 * que o compilador não pega: chave com erro de digitação, ou chave que alguém
 * apaga do arquivo. O {@link IssueCatalog} devolve a própria chave nesse caso —
 * visível no laudo, mas só se alguém olhar. Estes testes olham.
 */
class IssueCatalogTest {

    private final IssueCatalog catalog = catalogoReal();

    private static IssueCatalog catalogoReal() {
        var fonte = new ResourceBundleMessageSource();
        fonte.setBasename("messages");
        fonte.setDefaultEncoding("UTF-8");
        fonte.setFallbackToSystemLocale(false);
        return new IssueCatalog(fonte);
    }

    /**
     * Chaves cujo texto sai INTEIRO do catálogo — as que o ScoreService monta pelo
     * helper {@code achado(...)}. Lista explícita de propósito: é o contrato entre
     * o código e o arquivo de texto, e escrevê-lo à mão é o que faz alguém notar
     * quando adiciona achado novo.
     */
    private static final List<String> COMPLETAS = List.of(
            "NO_HTTPS_SUPPORT", "SSL_INVALID", "SSL_EXPIRED", "SSL_EXPIRING_SOON",
            "WEAK_TLS_PROTOCOL", "HTTP_NOT_REDIRECTING",
            "HEADERS_UNVERIFIED", "SERVER_VERSION_EXPOSED",
            "HSTS_MISSING", "HSTS_WEAK", "CONTENT_TYPE_MISSING",
            "CSP_MISSING", "CSP_WEAK", "XFRAME_MISSING",
            "REFERRER_POLICY_MISSING", "REFERRER_POLICY_WEAK", "PERMISSIONS_POLICY_MISSING",
            "CORS_REFLECTION_WITH_CREDENTIALS", "CORS_ORIGIN_REFLECTION",
            "CORS_WILDCARD_CREDENTIALS", "CORS_NULL_ORIGIN",
            "INSECURE_COOKIES", "DB_ERROR_LEAKAGE_SUSPECTED", "REFLECTED_XSS_SUSPECTED",
            "SENSITIVE_ROBOTS_PATHS", "SENSITIVE_FILE_EXPOSED", "DIRECTORY_LISTING",
            "SECURITY_TXT_MISSING", "OPEN_REDIRECT", "NO_WAF_DETECTED"
    );

    /**
     * Playground e introspection descrevem problemas diferentes — título e impacto
     * próprios — mas a correção é a mesma, então dividem uma recomendação sob a
     * chave base GRAPHQL. É a única chave com esse formato.
     */
    private static final List<String> GRAPHQL = List.of(
            "GRAPHQL_PLAYGROUND", "GRAPHQL_INTROSPECTION"
    );

    /**
     * Chaves sem impacto no catálogo de propósito: o impacto vem pronto de outro
     * serviço (DnsSecurityService, HttpMethodService, JwtSecurityService,
     * ApiDocsExposureService) ou do NVD, e não há o que traduzir do nosso lado.
     */
    private static final List<String> SEM_IMPACTO = List.of(
            "DNS_EMAIL_SPOOFING", "DANGEROUS_HTTP_METHOD", "JWT", "API_DOCS", "CVE"
    );

    // ── O modo de falha ──────────────────────────────────────────────────────

    @Test
    @DisplayName("chave ausente devolve a própria chave, para saltar aos olhos no laudo")
    void chaveAusenteApareceNoTexto() {
        assertEquals("issue.NAO_EXISTE.title", catalog.title("NAO_EXISTE"));
    }

    // ── A cobertura ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("todo achado tem título no catálogo")
    void todoAchadoTemTitulo() {
        for (String chave : todasAsChaves()) {
            assertResolvida(catalog.title(chave, "x", "y", "z"), chave, "title");
        }
    }

    @Test
    @DisplayName("toda correção existe — na própria chave, ou na base compartilhada")
    void todaCorrecaoExiste() {
        for (String chave : concat(COMPLETAS, SEM_IMPACTO)) {
            assertResolvida(catalog.recommendation(chave, "x"), chave, "recommendation");
        }
        // Os dois de GraphQL não têm recomendação própria: usam a da chave base.
        assertResolvida(catalog.recommendation("GRAPHQL"), "GRAPHQL", "recommendation");
    }

    @Test
    @DisplayName("achado com texto próprio tem impacto; os que herdam de outro serviço, não")
    void impactoSoOndeEleENosso() {
        for (String chave : concat(COMPLETAS, GRAPHQL)) {
            assertResolvida(catalog.impact(chave, "x"), chave, "impact");
        }
        for (String chave : SEM_IMPACTO) {
            assertEquals("issue." + chave + ".impact", catalog.impact(chave),
                    chave + " não deveria ter impacto no catálogo: ele vem do serviço "
                    + "que produziu o achado. Se passou a ter, o ScoreService precisa "
                    + "parar de repassar o texto de lá.");
        }
    }

    @Test
    @DisplayName("nenhuma mensagem sobra com parâmetro sem preencher")
    void parametrosSaoTodosPreenchidos() {
        // Passa argumentos de sobra: o que importa é que nenhum {0} escape para o
        // laudo. Sobra é ignorada pelo MessageFormat; falta apareceria como "{0}".
        for (String chave : concat(todasAsChaves(), List.of("GRAPHQL"))) {
            for (String texto : List.of(catalog.title(chave, "a", "b", "c"),
                                        catalog.impact(chave, "a", "b", "c"),
                                        catalog.recommendation(chave, "a", "b", "c"))) {
                assertFalse(texto.contains("{"), chave + " deixou parâmetro sem preencher: " + texto);
            }
        }
    }

    // ── Notas do breakdown ───────────────────────────────────────────────────

    /**
     * Chaves de nota. Nem toda nota tem achado correspondente — SSL_OK e
     * WAF_DETECTED existem só no breakdown — e nem todo achado desconta ponto,
     * então as duas listas não coincidem de propósito.
     */
    private static final List<String> NOTAS = List.of(
            "NO_HTTPS_SUPPORT", "SSL_INVALID", "SSL_OK", "SSL_EXPIRED", "SSL_EXPIRING_SOON",
            "WEAK_TLS_PROTOCOL", "HTTP_NOT_REDIRECTING",
            "HEADERS_UNVERIFIED", "SERVER_VERSION_EXPOSED",
            "HSTS_MISSING", "HSTS_WEAK", "CONTENT_TYPE_MISSING", "CSP_MISSING", "CSP_WEAK",
            "XFRAME_MISSING", "REFERRER_POLICY_MISSING", "REFERRER_POLICY_WEAK",
            "PERMISSIONS_POLICY_MISSING",
            "CORS_REFLECTION_WITH_CREDENTIALS", "CORS_ORIGIN_REFLECTION",
            "CORS_WILDCARD_CREDENTIALS", "CORS_NULL_ORIGIN",
            "INSECURE_COOKIES", "INPUT_SURFACE", "DB_ERROR_LEAKAGE_SUSPECTED",
            "REFLECTED_XSS_SUSPECTED", "RISKY_PORTS", "SENSITIVE_ROBOTS_PATHS",
            "SENSITIVE_FILE_EXPOSED", "DANGEROUS_HTTP_METHOD", "SECURITY_TXT_MISSING",
            "OPEN_REDIRECT", "DIRECTORY_LISTING", "PATH_TRAVERSAL", "SSRF", "HOST_HEADER",
            "SOURCE_MAP", "CRLF", "JWT", "API_DOCS",
            "GRAPHQL_PLAYGROUND", "GRAPHQL_INTROSPECTION",
            "DNS_EMAIL_SPOOFING", "NO_WAF_DETECTED", "WAF_DETECTED", "WAF_PROBE_BLOCKED",
            "CDN_DETECTED", "CVE"
    );

    @Test
    @DisplayName("toda nota do breakdown existe e não sobra parâmetro")
    void notasResolvemEPreenchem() {
        for (String chave : NOTAS) {
            String texto = catalog.note(chave, "a", "b", "c");
            assertFalse(texto.startsWith("note."),
                    "falta note." + chave + " em messages.properties");
            assertFalse(texto.contains("{"),
                    chave + " deixou parâmetro sem preencher: " + texto);
        }
    }

    @Test
    @DisplayName("a nota preserva o desconto — é ele que explica o score")
    void notaPreservaODesconto() {
        // Amostra copiada do ScoreService antes da extração. O número no texto é o
        // que justifica a conta na tela; perder isso quebra o breakdown em silêncio.
        assertEquals("HTTPS não suportado: -40", catalog.note("NO_HTTPS_SUPPORT"));
        assertEquals("HTTPS e certificado válido: OK", catalog.note("SSL_OK"));
        assertEquals("Cookies com flags de segurança ausentes: -10", catalog.note("INSECURE_COOKIES", 10));
        assertEquals("Protocolo TLS deprecated (TLSv1.0): -20", catalog.note("WEAK_TLS_PROTOCOL", "TLSv1.0"));
        assertEquals("SSRF (2 param(s)): -12", catalog.note("SSRF", 2, 12));
    }

    @Test
    @DisplayName("o fragmento do WAF entra na frase quando a sonda foi bloqueada")
    void fragmentoDoWafSeEncaixa() {
        // {1} recebe o fragmento ou vazio: WAF pode ser detectado sem bloquear a sonda.
        assertEquals("WAF detectado (Cloudflare, probe bloqueado): +3",
                catalog.note("WAF_DETECTED", "Cloudflare", catalog.note("WAF_PROBE_BLOCKED"), 3));
        assertEquals("WAF detectado (Cloudflare): +1",
                catalog.note("WAF_DETECTED", "Cloudflare", "", 1));
    }

    // ── A migração não reescreveu nada ───────────────────────────────────────

    @Test
    @DisplayName("o texto é o mesmo que estava embutido no código")
    void textoPreservado() {
        // Amostra copiada do ScoreService antes da extração. Se alguém "melhorar" a
        // redação junto com uma mudança técnica, este teste mostra.
        assertEquals("HTTPS não suportado", catalog.title("NO_HTTPS_SUPPORT"));
        assertEquals("Dados trafegam em plaintext — interceptação trivial.",
                catalog.impact("NO_HTTPS_SUPPORT"));
        assertEquals("Habilitar HTTPS com certificado válido (ex: Let's Encrypt).",
                catalog.recommendation("NO_HTTPS_SUPPORT"));
        assertEquals("Implementar CSP com default-src 'self' como base.",
                catalog.recommendation("CSP_MISSING"));
        assertEquals("3 cookie(s) com problemas de segurança", catalog.title("INSECURE_COOKIES", 3));
        assertEquals("Certificado próximo da expiração", catalog.title("SSL_EXPIRING_SOON"));
    }

    @Test
    @DisplayName("apóstrofo sobrevive ao MessageFormat na mensagem com parâmetro")
    void apostrofoNaoSomeQuandoHaParametro() {
        // MessageFormat trata ' como escape: sem dobrar no .properties, o título do
        // JWT sairia como "JWT inseguro em Authorization (alg=none)" — sem as aspas.
        String titulo = catalog.title("JWT", "Authorization", "none");

        assertEquals("JWT inseguro em 'Authorization' (alg=none)", titulo);
        assertTrue(titulo.contains("'Authorization'"));
    }

    private static List<String> todasAsChaves() {
        return concat(concat(COMPLETAS, GRAPHQL), SEM_IMPACTO);
    }

    private static List<String> concat(List<String> a, List<String> b) {
        return java.util.stream.Stream.concat(a.stream(), b.stream()).toList();
    }

    private static void assertResolvida(String texto, String chave, String campo) {
        assertFalse(texto.startsWith("issue."),
                "falta issue." + chave + "." + campo + " em messages.properties");
    }
}
