package com.joao.cyberaudit.service;

import com.joao.cyberaudit.config.LocaleConfig;
import com.joao.cyberaudit.model.CookieFinding;
import com.joao.cyberaudit.model.SSLInfo;
import com.joao.cyberaudit.model.ScoreResult;
import com.joao.cyberaudit.model.SecurityIssue;
import com.joao.cyberaudit.model.TlsDetails;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.ResourceBundleMessageSource;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * BUG-12: a análise de cookies lia atributo por substring e chutava o que é sessão.
 *
 * {@code contains("secure")} no Set-Cookie inteiro aceitava como Secure um cookie
 * chamado {@code secure_pref}, ou com "secure" no valor. O {@code XSRF-TOKEN} do
 * Laravel — feito para o JavaScript ler — contava como sessão por conter "token" e
 * perdia 10 pontos por não ter HttpOnly. O {@code connect.sid} do Express não era
 * sessão. Cookie de preferência sem flag custava 5, o mesmo que sessão sem SameSite. E
 * o achado agregado saía sempre MEDIUM, até quando o desconto era o de HIGH.
 */
class CookieAtributosTest {

    private final MessageCatalog catalog = catalogoReal();
    private final CookieSecurityService cookies = new CookieSecurityService(catalog);
    private final ScoreService scoreService = new ScoreService(catalog);

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

    private Optional<CookieFinding> achado(String setCookie) {
        List<CookieFinding> r = cookies.analyze(List.of(setCookie));
        assertTrue(r.size() <= 1);
        return r.stream().findFirst();
    }

    private CookieFinding achadoObrigatorio(String setCookie) {
        return achado(setCookie).orElseThrow(() -> new AssertionError("sem achado para: " + setCookie));
    }

    @Nested
    @DisplayName("atributos lidos como atributo, não como substring")
    class Atributos {

        @Test
        @DisplayName("cookie chamado secure_pref não ganha a flag Secure pelo nome")
        void nomeNaoViraFlag() {
            assertFalse(achadoObrigatorio("secure_pref=1; Path=/").isSecure());
        }

        @Test
        @DisplayName("\"secure\" e \"httponly\" no VALOR não viram flag")
        void valorNaoViraFlag() {
            CookieFinding f = achadoObrigatorio("PHPSESSID=secure-httponly-abc; Path=/");
            assertFalse(f.isSecure());
            assertFalse(f.isHttpOnly());
            assertEquals("HIGH", f.getRisk());
        }

        @Test
        @DisplayName("samesite=strict dentro do valor não é SameSite")
        void sameSiteNoValor() {
            assertEquals("MISSING", achadoObrigatorio("pref=samesite=strict-mode; Path=/").getSameSite());
        }

        @Test
        @DisplayName("atributo com caixa e espaço variados ainda é lido (RFC 6265 §5.2)")
        void caixaEEspaco() {
            assertTrue(achado("sessionid=x; secure; HTTPONLY; samesite = Lax").isEmpty(),
                    "Secure, HttpOnly e SameSite=Lax presentes: nada a apontar");
        }

        @Test
        @DisplayName("SameSite com valor desconhecido é ignorado pelo navegador — conta como ausente")
        void sameSiteInvalido() {
            CookieFinding f = achadoObrigatorio("sessionid=x; Secure; HttpOnly; SameSite=Foo");
            assertEquals("MISSING", f.getSameSite());
            assertEquals("MEDIUM", f.getRisk());
        }

        @Test
        @DisplayName("cookie de sessão completo não gera achado")
        void sessaoCompleta() {
            assertTrue(achado("__Host-sess=x; Path=/; Secure; HttpOnly; SameSite=Lax").isEmpty());
        }
    }

    @Nested
    @DisplayName("o que é sessão")
    class Sessao {

        @Test
        @DisplayName("connect.sid (Express) é sessão")
        void connectSid() {
            assertEquals("HIGH", achadoObrigatorio("connect.sid=s%3Aabc.def; Path=/").getRisk());
        }

        @Test
        @DisplayName("sid é sessão")
        void sid() {
            assertEquals("HIGH", achadoObrigatorio("sid=abc; Path=/").getRisk());
        }

        @Test
        @DisplayName("PHPSESSID com Secure mas sem HttpOnly continua HIGH")
        void phpsessidSemHttpOnly() {
            assertEquals("HIGH", achadoObrigatorio("PHPSESSID=abc; path=/; secure").getRisk());
        }

        @Test
        @DisplayName("sessão só sem SameSite é MEDIUM")
        void sessaoSemSameSite() {
            assertEquals("MEDIUM", achadoObrigatorio("sessionid=x; Secure; HttpOnly").getRisk());
        }
    }

    @Nested
    @DisplayName("cookie de CSRF")
    class Csrf {

        @Test
        @DisplayName("XSRF-TOKEN sem HttpOnly não é achado — o JavaScript precisa ler")
        void xsrfTokenDoLaravel() {
            assertTrue(achado("XSRF-TOKEN=eyJpdiI6; Path=/; Secure; SameSite=Lax").isEmpty());
        }

        @Test
        @DisplayName("csrftoken sem Secure é LOW e não reclama de HttpOnly")
        void csrftokenDoDjango() {
            CookieFinding f = achadoObrigatorio("csrftoken=abc; Path=/; SameSite=Lax");
            assertEquals("LOW", f.getRisk());
            assertFalse(f.getIssues().contains("HttpOnly"), f.getIssues());
        }
    }

    @Nested
    @DisplayName("cookie que não é de sessão")
    class NaoSessao {

        @Test
        @DisplayName("sem nenhuma flag é LOW — continua listado, sem desconto")
        void semFlagEhLow() {
            assertEquals("LOW", achadoObrigatorio("visitante=1; Path=/").getRisk());
        }

        @Test
        @DisplayName("\"sid\" no meio da palavra (inside_banner) não é sessão")
        void sidNoMeioDaPalavra() {
            assertEquals("LOW", achadoObrigatorio("inside_banner=1; Path=/").getRisk());
        }
    }

    @Nested
    @DisplayName("achado agregado no score")
    class Agregado {

        private ScoreResult score(String... setCookies) {
            List<CookieFinding> achados = cookies.analyze(Arrays.asList(setCookies));
            SSLInfo    ssl = new SSLInfo(true, true, "2030-01-01", 300, "Certificado válido", 365);
            TlsDetails tls = new TlsDetails("TLSv1.3", "TLS_AES_256_GCM_SHA384", false, "OK");
            return scoreService.calculate(
                    ssl, tls, Map.of(), true,
                    false, false, false, false, false, List.of(),
                    null, achados, List.of(), false,
                    List.of(), List.of(), true,
                    List.of(), List.of(), null, null,
                    List.of(), List.of(), List.of(), List.of(),
                    List.of(), List.of(), List.of(), List.of(), List.of());
        }

        private Optional<SecurityIssue> issue(ScoreResult r) {
            return r.getIssues().stream().filter(i -> "INSECURE_COOKIES".equals(i.getId())).findFirst();
        }

        @Test
        @DisplayName("com cookie HIGH, o achado é HIGH e custa 10")
        void severidadeDoPior() {
            ScoreResult r = score("PHPSESSID=abc; path=/; secure");
            assertEquals("HIGH", issue(r).orElseThrow().getSeverity(),
                    "o card do cookie diz HIGH; o achado não pode dizer MEDIUM");
            assertEquals(90, r.getScore());
        }

        @Test
        @DisplayName("com cookie MEDIUM, o achado é MEDIUM e custa 5")
        void medium() {
            ScoreResult r = score("sessionid=x; Secure; HttpOnly");
            assertEquals("MEDIUM", issue(r).orElseThrow().getSeverity());
            assertEquals(95, r.getScore());
        }

        @Test
        @DisplayName("só cookies LOW: nenhum achado e nenhum desconto")
        void soLow() {
            ScoreResult r = score("visitante=1; Path=/", "csrftoken=abc; Path=/; SameSite=Lax");
            assertTrue(issue(r).isEmpty(), "LOW é informativo: " + r.getIssues());
            assertEquals(100, r.getScore());
        }

        @Test
        @DisplayName("o título conta só os cookies que custam ponto")
        void tituloContaOsQueCustam() {
            ScoreResult r = score("PHPSESSID=abc; path=/; secure", "visitante=1; Path=/");
            assertTrue(issue(r).orElseThrow().getTitle().startsWith("1 "), issue(r).orElseThrow().getTitle());
        }

        @Test
        @DisplayName("o site Laravel padrão (XSRF-TOKEN + laravel_session) não perde ponto")
        void laravelPadrao() {
            ScoreResult r = score(
                    "XSRF-TOKEN=eyJpdiI6; expires=Thu, 12 Nov 2026 14:00:00 GMT; Max-Age=7200; path=/; secure; samesite=lax",
                    "laravel_session=eyJpdiI6; expires=Thu, 12 Nov 2026 14:00:00 GMT; Max-Age=7200; path=/; secure; httponly; samesite=lax");
            assertTrue(issue(r).isEmpty(), r.getIssues().toString());
            assertEquals(100, r.getScore());
        }
    }
}
