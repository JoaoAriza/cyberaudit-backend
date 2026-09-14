package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.CookieFinding;
import com.joao.cyberaudit.model.FormSurfaceResult;
import com.joao.cyberaudit.model.ImpactLevel;
import com.joao.cyberaudit.model.JwtSecurityFinding;
import com.joao.cyberaudit.model.ScanResult;
import com.joao.cyberaudit.model.TechFingerprintResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

    // ── Plataforma de loja: aviso, nao nivel ─────────────────────────────────

    private TechFingerprintResult tech(String cms, String... bibliotecas) {
        return TechFingerprintResult.builder().cms(cms).libraries(List.of(bibliotecas)).build();
    }

    @Test
    @DisplayName("home de loja Shopify sem formulario continua VITRINE, com aviso da plataforma")
    void plataformaNaoEleva() {
        // Antes: detectar a plataforma marcava PAYMENT em qualquer pagina da loja.
        // A home nao coleta nada; o checkout e da plataforma, nao do lojista.
        ScanResult.ScanResultBuilder home = base("https://loja.com.br/").techFingerprint(tech("Shopify"));

        ImpactLabelService.Avaliacao a = service.assess(home.build());

        assertEquals(ImpactLevel.SHOWCASE, a.level());
        assertEquals("Shopify", a.managedPlatform());
    }

    @Test
    @DisplayName("Tiendanube aparece com o nome brasileiro, Nuvemshop")
    void tiendanubeViraNuvemshop() {
        assertEquals("Nuvemshop", service.assess(
                base("https://loja.com.br/").techFingerprint(tech("Tiendanube")).build()).managedPlatform());
    }

    @Test
    @DisplayName("WooCommerce e instalado pelo lojista: sem aviso de plataforma")
    void wooCommerceNaoEhGerida() {
        ScanResult r = base("https://loja.com.br/").techFingerprint(tech("WordPress", "WooCommerce", "jQuery 3.6.0")).build();
        assertNull(service.assess(r).managedPlatform());
    }

    // ── Sinais: o porque do nivel ────────────────────────────────────────────

    private List<String> sinais(ImpactLabelService.Avaliacao a) {
        return a.signals().stream().map(s -> s.getSource() + ":" + s.getDetail()).toList();
    }

    @Test
    @DisplayName("checkout com cartao traz os dois motivos: o campo e o caminho")
    void sinaisDoCheckout() {
        ScanResult r = base("https://loja.com.br/checkout")
                .formSurface(form(true, false, true, true)).build();

        assertEquals(List.of("FORM:payment-field", "PATH:/checkout"), sinais(service.assess(r)));
    }

    @Test
    @DisplayName("so os sinais do nivel vencedor: a senha do checkout nao entra no porque")
    void soSinaisDoNivelVencedor() {
        ScanResult r = base("https://loja.com.br/checkout")
                .formSurface(form(true, true, true, false))
                .cookieIssues(List.of(cookie("session"))).build();

        assertEquals(List.of("PATH:/checkout"), sinais(service.assess(r)));
    }

    @Test
    @DisplayName("conta: o cookie de sessao e nomeado, o de analytics nao")
    void sinaisDeConta() {
        ScanResult r = base("https://loja.com.br/")
                .cookieIssues(List.of(cookie("_hjSession_1873402"), cookie("PHPSESSID"))).build();

        assertEquals(List.of("COOKIES:PHPSESSID"), sinais(service.assess(r)));
    }

    @Test
    @DisplayName("vitrine nao tem motivo para listar")
    void vitrineSemSinais() {
        assertTrue(service.assess(base("https://acabamentos-silva.com.br/").build()).signals().isEmpty());
    }

    @Test
    @DisplayName("rotular grava nivel, sinais e plataforma no resultado")
    void rotularGravaTudo() {
        ScanResult r = base("https://loja.com.br/contato")
                .formSurface(form(true, false, true, false))
                .techFingerprint(tech("VTEX")).build();

        service.rotular(r);

        assertEquals(ImpactLevel.CONTACT, r.getImpact());
        assertEquals(List.of("FORM:pii-field", "FORM:form"),
                r.getImpactSignals().stream().map(s -> s.getSource() + ":" + s.getDetail()).toList());
        assertEquals("VTEX", r.getManagedPlatform());
    }
}
