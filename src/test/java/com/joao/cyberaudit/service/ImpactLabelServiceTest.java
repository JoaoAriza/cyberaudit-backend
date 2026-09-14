package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.CookieFinding;
import com.joao.cyberaudit.model.FormSurfaceResult;
import com.joao.cyberaudit.model.ImpactLevel;
import com.joao.cyberaudit.model.JwtSecurityFinding;
import com.joao.cyberaudit.model.ScanResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * O rotulo responde "o que ha para perder aqui", nao "quao fragil esta".
 *
 * O caso que motivou: a home e o /checkout da mesma loja saem com a mesma cor no
 * laudo, e um achado sem consequencia real se apresenta com o mesmo peso de um
 * vazamento de dado de cliente. O nivel mais alto que casar vence.
 */
class ImpactLabelServiceTest {

    private final ImpactLabelService service = new ImpactLabelService();

    private ScanResult.ScanResultBuilder base(String url) {
        return ScanResult.builder().url(url).formSurface(FormSurfaceResult.vazio());
    }

    private FormSurfaceResult form(boolean temForm, boolean senha, boolean pii, boolean cartao) {
        return FormSurfaceResult.builder()
                .hasForm(temForm).hasPasswordField(senha)
                .collectsPii(pii).hasPaymentField(cartao)
                .evidence(List.of()).build();
    }

    private CookieFinding cookie(String nome) {
        CookieFinding c = new CookieFinding();
        c.setName(nome);
        return c;
    }

    // ── SHOWCASE ─────────────────────────────────────────────────────────────

    @Test
    @DisplayName("vitrine do Maps: nada coletado, nada em risco")
    void vitrine() {
        assertEquals(ImpactLevel.SHOWCASE,
                service.derive(base("https://acabamentos-silva.com.br/").build()));
    }

    @Test
    @DisplayName("analytics com 'session'/'user' no nome nao transforma vitrine em conta")
    void cookieDeInfraNaoConta() {
        // Estes DOIS e que exercitam a exclusao: "_hjsession_..." contem "sess" e
        // "ajs_user_id" contem "user" — os mesmos fragmentos que marcam sessao.
        // Hotjar e Segment estao em boa parte dos sites institucionais, entao sem a
        // exclusao por prefixo a vitrine sairia como ACCOUNT.
        ScanResult r = base("https://acabamentos-silva.com.br/")
                .cookieIssues(List.of(
                        cookie("__cf_bm"),
                        cookie("_hjSession_1873402"),
                        cookie("ajs_user_id"),
                        cookie("_ga_9XKQ2R")))
                .build();
        assertEquals(ImpactLevel.SHOWCASE, service.derive(r),
                "cookie de analytics nao e cookie de sessao autenticada");
    }

    @Test
    @DisplayName("caminho parecido nao casa: /carta-de-servicos nao e /cart")
    void caminhoParecidoNaoCasa() {
        assertEquals(ImpactLevel.SHOWCASE,
                service.derive(base("https://loja.com.br/carta-de-servicos").build()));
    }

    // ── CONTACT ──────────────────────────────────────────────────────────────

    @Test
    @DisplayName("formulario de contato coleta dado pessoal")
    void contato() {
        ScanResult r = base("https://loja.com.br/contato")
                .formSurface(form(true, false, true, false)).build();
        assertEquals(ImpactLevel.CONTACT, service.derive(r));
    }

    // ── ACCOUNT ──────────────────────────────────────────────────────────────

    @Test
    @DisplayName("campo de senha indica area autenticada")
    void senhaEhConta() {
        ScanResult r = base("https://loja.com.br/entrar")
                .formSurface(form(true, true, true, false)).build();
        assertEquals(ImpactLevel.ACCOUNT, service.derive(r));
    }

    @Test
    @DisplayName("cookie de sessao real indica conta")
    void cookieDeSessao() {
        ScanResult r = base("https://loja.com.br/")
                .cookieIssues(List.of(cookie("__cf_bm"), cookie("session"))).build();
        assertEquals(ImpactLevel.ACCOUNT, service.derive(r));
    }

    @Test
    @DisplayName("JWT encontrado indica conta")
    void jwtEhConta() {
        ScanResult r = base("https://loja.com.br/")
                .jwtSecurity(List.of(JwtSecurityFinding.builder().source("access_token").build()))
                .build();
        assertEquals(ImpactLevel.ACCOUNT, service.derive(r));
    }

    @Test
    @DisplayName("caminho de login indica conta")
    void caminhoDeLogin() {
        assertEquals(ImpactLevel.ACCOUNT,
                service.derive(base("https://loja.com.br/minha-conta/pedidos").build()));
    }

    // ── PAYMENT ──────────────────────────────────────────────────────────────

    @Test
    @DisplayName("caminho de checkout indica pagamento")
    void caminhoDeCheckout() {
        assertEquals(ImpactLevel.PAYMENT,
                service.derive(base("https://loja.com.br/checkout/v3/start/abc").build()));
    }

    @Test
    @DisplayName("campo de cartao indica pagamento mesmo sem caminho obvio")
    void campoDeCartao() {
        ScanResult r = base("https://loja.com.br/finalizar")
                .formSurface(form(true, false, true, true)).build();
        assertEquals(ImpactLevel.PAYMENT, service.derive(r));
    }

    @Test
    @DisplayName("o nivel mais alto vence: checkout com senha e PAYMENT, nao ACCOUNT")
    void maisAltoVence() {
        ScanResult r = base("https://loja.com.br/checkout")
                .formSurface(form(true, true, true, false))
                .cookieIssues(List.of(cookie("session"))).build();
        assertEquals(ImpactLevel.PAYMENT, service.derive(r));
    }

    // ── O caso real ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("arrazzestore: a home e a tela de pagamento saem em niveis diferentes")
    void casoArrazzestore() {
        ScanResult home = base("https://www.arrazzestore.com.br/")
                .finalUrl("https://www.arrazzestore.com.br/")
                .cookieIssues(List.of(cookie("__cf_bm"))).build();

        ScanResult checkout = base("https://www.arrazzestore.com.br/checkout/v3/start/206-d85/from-store")
                .finalUrl("https://www.arrazzestore.com.br/checkout/v3/start/206-d85/from-store")
                .cookieIssues(List.of(cookie("__cf_bm"), cookie("session"))).build();

        assertEquals(ImpactLevel.SHOWCASE, service.derive(home));
        assertEquals(ImpactLevel.PAYMENT, service.derive(checkout));
    }

    @Test
    @DisplayName("resultado nulo nao quebra a derivacao")
    void nuloNaoQuebra() {
        assertEquals(ImpactLevel.SHOWCASE, service.derive(null));
    }
}
