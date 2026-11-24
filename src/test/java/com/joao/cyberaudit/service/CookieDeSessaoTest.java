package com.joao.cyberaudit.service;

import com.joao.cyberaudit.config.LocaleConfig;
import com.joao.cyberaudit.model.CookieFinding;
import com.joao.cyberaudit.model.FormSurfaceResult;
import com.joao.cyberaudit.model.ImpactSource;
import com.joao.cyberaudit.model.ScanResult;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.ResourceBundleMessageSource;

import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * BUG-21: "é cookie de sessão?" tinha duas respostas.
 *
 * O card do cookie (risco e nota) decide pelo {@code CookieSecurityService.tipo}. O
 * painel "O que está em jogo" ({@code ImpactLabelService}) tinha lista própria, por
 * "contém": chamava de sessão o token CSRF ("token"), o {@code inside_banner} ("sid") e
 * o {@code user_pref} ("user"). E o card chamava de sessão o analytics do Hotjar
 * ({@code _hjSession_1873402}, por "session"), que o painel já descartava.
 *
 * A tabela abaixo é a resposta certa para cada nome, e os dois lados são conferidos
 * contra ela. O {@code CookieFinding} sai do {@code CookieSecurityService} real, como
 * no scan.
 */
class CookieDeSessaoTest {

    private final CookieSecurityService cookies = new CookieSecurityService(catalogoReal());
    private final ImpactLabelService impacto = new ImpactLabelService();

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

    /** Nome do cookie e se ele é de sessão. Todos vão sem flag nenhuma. */
    static Stream<Arguments> tabela() {
        return Stream.of(
                // Sessão de verdade.
                Arguments.of("PHPSESSID", true),
                Arguments.of("JSESSIONID", true),
                Arguments.of("ASP.NET_SessionId", true),
                Arguments.of("connect.sid", true),
                Arguments.of("sid", true),
                Arguments.of("app-sid", true),
                Arguments.of("laravel_session", true),
                Arguments.of("sub100_sites_session", true),
                Arguments.of("auth_token", true),
                Arguments.of("jwt", true),
                Arguments.of("remember_login", true),
                // O painel chamava de sessão.
                Arguments.of("XSRF-TOKEN", false),
                Arguments.of("csrftoken", false),
                Arguments.of("_csrf", false),
                Arguments.of("inside_banner", false),
                Arguments.of("user_pref", false),
                Arguments.of("usuario_tema", false),
                // O card chamava de sessão.
                Arguments.of("_hjSession_1873402", false),
                Arguments.of("_hjSessionUser_1873402", false),
                Arguments.of("_hjSessionRejected", false),
                Arguments.of("_hjIncludedInSessionSample_1873402", false),
                Arguments.of("_hjAbsoluteSessionInProgress", false),
                // Os dois já concordavam.
                Arguments.of("__cf_bm", false),
                Arguments.of("_ga_9XKQ2R", false),
                Arguments.of("ajs_user_id", false),
                Arguments.of("visitante", false));
    }

    private CookieFinding card(String nome) {
        List<CookieFinding> r = cookies.analyze(List.of(nome + "=x; Path=/"));
        assertEquals(1, r.size(), "sem flag nenhuma, todo cookie entra no card: " + nome);
        return r.get(0);
    }

    /** Os nomes que o painel lista como "Cookies de sessão", na ordem. */
    private List<String> painel(String... setCookies) {
        ScanResult r = ScanResult.builder()
                .url("http://cookies-mock:8080/nomes").httpStatus(200)
                .formSurface(FormSurfaceResult.builder().analyzed(true).evidence(List.of()).build())
                .cookieIssues(cookies.analyze(List.of(setCookies)))
                .build();
        return impacto.assess(r).indicators().stream()
                .filter(s -> s.getSource() == ImpactSource.COOKIES)
                .map(s -> s.getDetail())
                .toList();
    }

    @ParameterizedTest(name = "card: {0} é sessão? {1}")
    @MethodSource("tabela")
    @DisplayName("o card decide pela tabela: sessão sem flag é HIGH, o resto é LOW")
    void cardSegueATabela(String nome, boolean sessao) {
        assertEquals(sessao ? "HIGH" : "LOW", card(nome).getRisk(), nome);
    }

    @ParameterizedTest(name = "painel: {0} é sessão? {1}")
    @MethodSource("tabela")
    @DisplayName("o painel decide pela mesma tabela")
    void painelSegueATabela(String nome, boolean sessao) {
        assertEquals(sessao ? List.of(nome) : List.of(), painel(nome + "=x; Path=/"), nome);
    }

    /**
     * A lista de CDN e analytics que o painel descartava continua descartada nos dois.
     * No card, só o Hotjar precisava de regra: os outros nomes não têm fragmento de
     * sessão e já saíam LOW.
     */
    @ParameterizedTest(name = "lista antiga do painel: {0}")
    @ValueSource(strings = {"__cf_bm", "_cfuvid", "cf_clearance", "__cfruid", "__cflb",
            "_ga", "_ga_9XKQ2R", "_gid", "_gat", "_gat_UA-123-1", "_gcl_au", "_fbp", "_fbc",
            "_clck", "_clsk", "_hjSession_1873402", "_hjSessionUser_1873402",
            "ajs_user_id", "ajs_anonymous_id"})
    @DisplayName("CDN e analytics não são sessão, nem no card nem no painel")
    void listaAntigaDoPainel(String nome) {
        assertEquals("LOW", card(nome).getRisk(), nome);
        assertEquals(List.of(), painel(nome + "=x; Path=/"), nome);
    }

    @Test
    @DisplayName("o alvo /nomes do cookies-mock: o painel lista só o laravel_session")
    void alvoNomes() {
        // Antes: csrftoken, inside_banner e user_pref, e o teto de três indícios
        // deixava de fora o laravel_session, o único de sessão.
        assertEquals(List.of("laravel_session"), painel(
                "csrftoken=qa-csrf; Path=/",
                "inside_banner=1; Path=/",
                "user_pref=escuro; Path=/",
                "_hjSession_1873402=qa-hotjar; Path=/",
                "laravel_session=qa-sessao; Path=/"));
    }

    @Test
    @DisplayName("sanidade: a tabela tem os dois lados")
    void tabelaTemOsDoisLados() {
        List<Boolean> respostas = tabela().map(a -> (Boolean) a.get()[1]).toList();
        assertTrue(respostas.contains(true) && respostas.contains(false));
    }
}
