package com.joao.cyberaudit.service;

import com.joao.cyberaudit.config.LocaleConfig;
import com.joao.cyberaudit.dto.ComplianceReport;
import com.joao.cyberaudit.model.CookieFinding;
import com.joao.cyberaudit.model.ScanResult;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.ResourceBundleMessageSource;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Os itens de cookie do compliance (LGPD Art. 49) dizem o mesmo que o card do cookie.
 *
 * Regressão do BUG-13 (cyberaudit-qa): o compliance procurava SameSite {@code null} ou
 * vazio, e o {@link CookieSecurityService} grava a ausência como {@code "MISSING"}. O item
 * "Cookies sem atributo SameSite" nunca aparecia. Na mesma conta, o item de HttpOnly
 * olhava só a flag e contava o token CSRF, que o card isenta desde o BUG-12.
 *
 * O {@code ScanResult} sai do {@code CookieSecurityService} de verdade, a partir do
 * Set-Cookie. Um {@code CookieFinding} montado à mão foi como a divergência passou: quem
 * monta à mão escolhe o formato que o compliance espera, e não o que o serviço grava.
 */
class ComplianceCookiesTest {

    private static final String SECURE   = "Cookies sem flag Secure — transmitidos em conexões HTTP";
    private static final String HTTPONLY = "Cookies sem flag HttpOnly — acessíveis via JavaScript";
    private static final String SAMESITE = "Cookies sem atributo SameSite — vulneráveis a CSRF";

    private final MessageCatalog catalog = catalogoReal();
    private final CookieSecurityService cookies = new CookieSecurityService(catalog);
    private final ComplianceMappingService compliance = new ComplianceMappingService(catalog);

    private static MessageCatalog catalogoReal() {
        var fonte = new ResourceBundleMessageSource();
        fonte.setBasename("messages");
        fonte.setDefaultEncoding("UTF-8");
        fonte.setFallbackToSystemLocale(false);
        return new MessageCatalog(fonte);
    }

    @BeforeEach
    void idioma() {
        LocaleContextHolder.setLocale(LocaleConfig.PADRAO);
    }

    @AfterEach
    void limpaIdioma() {
        LocaleContextHolder.resetLocaleContext();
    }

    private List<CookieFinding> cards(String... setCookies) {
        return cookies.analyze(List.of(setCookies));
    }

    /** Não-conformidades do Art. 49 para um resultado que só tem os cookies. */
    private List<String> art49(List<CookieFinding> cards) {
        ScanResult r = ScanResult.builder().headers(Map.of()).cookieIssues(cards).build();
        ComplianceReport rel = compliance.generate(r);
        return rel.getLgpdItems().stream()
                .filter(i -> "Art. 49".equals(i.getReference()))
                .findFirst().orElseThrow()
                .getFindings();
    }

    private List<String> art49(String... setCookies) {
        return art49(cards(setCookies));
    }

    // ── SameSite (o BUG-13) ─────────────────────────────────────────────────

    @Test
    @DisplayName("cookie de sessão sem SameSite: o item de SameSite aparece")
    void sessaoSemSameSite() {
        assertEquals(List.of(SAMESITE), art49("sessionid=x; Path=/; Secure; HttpOnly"));
    }

    @Test
    @DisplayName("SameSite com valor inválido conta como ausente, igual ao card")
    void sameSiteInvalido() {
        assertEquals(List.of(SAMESITE), art49("sessionid=x; Secure; HttpOnly; SameSite=Bogus"));
    }

    @Test
    @DisplayName("cookie de preferência sem SameSite também conta: é o que o card lista")
    void preferenciaSemSameSite() {
        assertEquals(List.of(SAMESITE), art49("theme=dark; Secure; HttpOnly"));
    }

    // ── HttpOnly do token CSRF (lateral, mesma raiz) ────────────────────────

    @Test
    @DisplayName("token CSRF sem nenhuma flag: Secure e SameSite, sem o item de HttpOnly")
    void tokenCsrfSemFlags() {
        assertEquals(List.of(SECURE, SAMESITE), art49("XSRF-TOKEN=x; Path=/"));
    }

    @Test
    @DisplayName("token CSRF com SameSite e sem Secure: só o item de Secure")
    void tokenCsrfSemSecure() {
        assertEquals(List.of(SECURE), art49("csrftoken=x; Path=/; SameSite=Lax"));
    }

    // ── Controles ───────────────────────────────────────────────────────────

    @Test
    @DisplayName("controle: cookie de sessão com as três flags não gera item nenhum")
    void sessaoCompleta() {
        assertEquals(List.of(), art49("sessionid=x; Path=/; Secure; HttpOnly; SameSite=Lax"));
    }

    @Test
    @DisplayName("controle: cookie de sessão sem HttpOnly continua com o item de HttpOnly")
    void sessaoSemHttpOnly() {
        assertEquals(List.of(HTTPONLY), art49("sessionid=x; Secure; SameSite=Strict"));
    }

    @Test
    @DisplayName("controle: SameSite=None sem Secure é o item de Secure, não o de SameSite")
    void noneSemSecure() {
        assertEquals(List.of(SECURE), art49("sessionid=x; HttpOnly; SameSite=None"));
    }

    @Test
    @DisplayName("os cinco cookies do cookies-mock (SCAN-09): os três itens")
    void cookiesMock() {
        assertEquals(List.of(SECURE, HTTPONLY, SAMESITE), art49(
                "PHPSESSID=qa-sessao; Path=/; Secure",
                "XSRF-TOKEN=qa-csrf; Path=/; Secure; SameSite=Lax",
                "secure_pref=1; Path=/",
                "visitante=1; Path=/",
                "connect.sid=s%3Aqa-express; Path=/; HttpOnly; SameSite=Lax"));
    }

    // ── A regra geral ───────────────────────────────────────────────────────

    /**
     * Para cada Set-Cookie: o item do compliance aparece se, e só se, o card do cookie
     * lista o problema correspondente. É a forma geral dos testes acima, e é o que pega
     * a próxima divergência entre os dois serviços.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("setCookies")
    void complianceDizOQueOCardDiz(String setCookie) {
        List<CookieFinding> cards = cards(setCookie);
        List<String> itens = art49(cards);

        assertEquals(cardLista(cards, "COOKIE_SEM_SECURE"), itens.contains(SECURE), "Secure");
        assertEquals(cardLista(cards, "COOKIE_SEM_HTTPONLY"), itens.contains(HTTPONLY), "HttpOnly");
        assertEquals(cardLista(cards, "COOKIE_SEM_SAMESITE"), itens.contains(SAMESITE), "SameSite");
    }

    /**
     * O código em {@code problems} e o texto em {@code issues} são o mesmo veredito: um
     * código por texto, na mesma ordem. A tela desenha os avisos pelo código.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("setCookies")
    void codigosBatemComOTexto(String setCookie) {
        for (CookieFinding c : cards(setCookie)) {
            assertEquals(c.getProblems().stream().map(catalog::evidence).toList(),
                    List.of(c.getIssues().split("; ")));
        }
    }

    static Stream<String> setCookies() {
        return Stream.of(
            "sessionid=x",
            "sessionid=x; Secure",
            "sessionid=x; HttpOnly",
            "sessionid=x; SameSite=Lax",
            "sessionid=x; Secure; HttpOnly",
            "sessionid=x; Secure; SameSite=None",
            "sessionid=x; HttpOnly; SameSite=None",
            "sessionid=x; Secure; HttpOnly; SameSite=strict",
            "sessionid=x; Secure; HttpOnly; SameSite=",
            "XSRF-TOKEN=x",
            "XSRF-TOKEN=x; Secure",
            "XSRF-TOKEN=x; Secure; SameSite=Strict",
            "_csrf=x; HttpOnly",
            "theme=dark",
            "theme=dark; Secure; HttpOnly; SameSite=Lax",
            "connect.sid=s; HttpOnly; SameSite=Lax",
            "inside_banner=1; Secure; HttpOnly");
    }

    private boolean cardLista(List<CookieFinding> cards, String problema) {
        String texto = catalog.evidence(problema);
        return cards.stream().anyMatch(c -> c.getIssues() != null && c.getIssues().contains(texto));
    }

    @Test
    @DisplayName("sanidade: o texto de cada problema do card é distinto, então cardLista não confunde")
    void textosDistintos() {
        String secure   = catalog.evidence("COOKIE_SEM_SECURE");
        String httpOnly = catalog.evidence("COOKIE_SEM_HTTPONLY");
        String sameSite = catalog.evidence("COOKIE_SEM_SAMESITE");
        String none     = catalog.evidence("COOKIE_SAMESITE_NONE_SEM_SECURE");
        for (String a : List.of(secure, httpOnly, sameSite, none)) {
            for (String b : List.of(secure, httpOnly, sameSite, none)) {
                if (a != b) assertFalse(a.contains(b), "'" + a + "' contém '" + b + "'");
            }
        }
        assertTrue(art49().isEmpty(), "sem cookie, sem item de cookie");
    }
}
