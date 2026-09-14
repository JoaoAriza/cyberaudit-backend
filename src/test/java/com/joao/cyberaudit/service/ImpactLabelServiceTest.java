package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.CookieFinding;
import com.joao.cyberaudit.model.FormSurfaceResult;
import com.joao.cyberaudit.model.ImpactLevel;
import com.joao.cyberaudit.model.ImpactSignal;
import com.joao.cyberaudit.model.ImpactUndetermined;
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
 * O rotulo responde "o que ha para perder NESTA pagina", nao "quao fragil esta".
 *
 * O nivel vem so dos campos da pagina. Os casos de producao que fixaram isso estao
 * no bloco "Casos reais": um /checkout/login bloqueado que saia PAGAMENTO pelo
 * endereco e uma home de imobiliaria que saia CONTA por um cookie anonimo.
 */
class ImpactLabelServiceTest {

    private final ImpactLabelService service = new ImpactLabelService();

    /** Pagina lida (HTML analisado) com os campos pedidos. */
    private FormSurfaceResult pagina(boolean temForm, boolean senha, boolean pii, boolean cartao) {
        return FormSurfaceResult.builder().analyzed(true)
                .hasForm(temForm).hasPasswordField(senha)
                .collectsPii(pii).hasPaymentField(cartao)
                .evidence(List.of()).build();
    }

    /** HTTP 200, pagina lida, nenhum campo. */
    private ScanResult.ScanResultBuilder base(String url) {
        return ScanResult.builder().url(url).httpStatus(200).formSurface(pagina(false, false, false, false));
    }

    private CookieFinding cookie(String nome) {
        CookieFinding c = new CookieFinding();
        c.setName(nome);
        return c;
    }

    private TechFingerprintResult tech(String cms, String... bibliotecas) {
        return TechFingerprintResult.builder().cms(cms).libraries(List.of(bibliotecas)).build();
    }

    private List<String> texto(List<ImpactSignal> sinais) {
        return sinais.stream().map(s -> s.getSource() + ":" + s.getDetail()).toList();
    }

    // ── Nivel pelos campos ───────────────────────────────────────────────────

    @Test
    @DisplayName("vitrine do Maps: pagina lida, nenhum campo, nada em risco")
    void vitrine() {
        ImpactLabelService.Avaliacao a = service.assess(base("https://acabamentos-silva.com.br/").build());
        assertEquals(ImpactLevel.SHOWCASE, a.level());
        assertTrue(a.signals().isEmpty());
        assertNull(a.undetermined());
    }

    @Test
    @DisplayName("formulario de busca sozinho nao e coleta de dado")
    void buscaNaoEhContato() {
        // A primeira versao contava QUALQUER <form> como CONTATO — e toda imobiliaria
        // e toda loja tem formulario de busca.
        ScanResult r = base("https://imobiliaria.com.br/").formSurface(pagina(true, false, false, false)).build();
        assertEquals(ImpactLevel.SHOWCASE, service.derive(r));
    }

    @Test
    @DisplayName("campo de dado pessoal: CONTATO")
    void contato() {
        ScanResult r = base("https://loja.com.br/").formSurface(pagina(false, false, true, false)).build();
        ImpactLabelService.Avaliacao a = service.assess(r);
        assertEquals(ImpactLevel.CONTACT, a.level());
        assertEquals(List.of("FORM:pii-field"), texto(a.signals()));
    }

    @Test
    @DisplayName("campo de senha: CONTA")
    void senhaEhConta() {
        ScanResult r = base("https://loja.com.br/entrar").formSurface(pagina(true, true, true, false)).build();
        assertEquals(ImpactLevel.ACCOUNT, service.derive(r));
    }

    @Test
    @DisplayName("campo de cartao: PAGAMENTO, e o nivel mais alto vence")
    void cartaoEhPagamento() {
        ScanResult r = base("https://loja.com.br/finalizar").formSurface(pagina(true, true, true, true)).build();
        ImpactLabelService.Avaliacao a = service.assess(r);
        assertEquals(ImpactLevel.PAYMENT, a.level());
        assertEquals(List.of("FORM:payment-field"), texto(a.signals()));
    }

    // ── O endereco nao decide ────────────────────────────────────────────────

    @Test
    @DisplayName("/checkout/login lido e com senha e CONTA, nao PAGAMENTO")
    void checkoutLidoSemCartao() {
        ScanResult r = base("https://www.petz.com.br/checkout/login/indexLogado_Loja")
                .formSurface(pagina(true, true, true, false)).build();
        assertEquals(ImpactLevel.ACCOUNT, service.derive(r));
    }

    @Test
    @DisplayName("/minha-conta sem campo nenhum e VITRINE: o endereco nao e evidencia")
    void caminhoDeContaSemCampo() {
        assertEquals(ImpactLevel.SHOWCASE, service.derive(base("https://loja.com.br/minha-conta/pedidos").build()));
    }

    // ── Indicios do dominio ──────────────────────────────────────────────────

    @Test
    @DisplayName("cookie de sessao nao sobe o nivel: vira indicio")
    void cookieDeSessaoEhIndicio() {
        ScanResult r = base("https://loja.com.br/").cookieIssues(List.of(cookie("PHPSESSID"))).build();
        ImpactLabelService.Avaliacao a = service.assess(r);
        assertEquals(ImpactLevel.SHOWCASE, a.level());
        assertEquals(List.of("COOKIES:PHPSESSID"), texto(a.indicators()));
    }

    @Test
    @DisplayName("cookie de analytics com 'session'/'user' no nome nem vira indicio")
    void cookieDeInfraNaoEhIndicio() {
        ScanResult r = base("https://acabamentos-silva.com.br/")
                .cookieIssues(List.of(cookie("__cf_bm"), cookie("_hjSession_1873402"),
                        cookie("ajs_user_id"), cookie("_ga_9XKQ2R")))
                .build();
        assertTrue(service.assess(r).indicators().isEmpty());
    }

    @Test
    @DisplayName("JWT nao sobe o nivel: vira indicio com a origem do token")
    void jwtEhIndicio() {
        ScanResult r = base("https://loja.com.br/")
                .jwtSecurity(List.of(JwtSecurityFinding.builder().source("access_token").build()))
                .build();
        ImpactLabelService.Avaliacao a = service.assess(r);
        assertEquals(ImpactLevel.SHOWCASE, a.level());
        assertEquals(List.of("JWT:access_token"), texto(a.indicators()));
    }

    // ── Pagina que nao foi lida ──────────────────────────────────────────────

    @Test
    @DisplayName("resposta 2xx sem HTML: nao determinado, e nao vitrine")
    void paginaSemHtml() {
        ScanResult r = base("https://loja.com.br/").formSurface(FormSurfaceResult.vazio()).build();
        ImpactLabelService.Avaliacao a = service.assess(r);
        assertNull(a.level());
        assertEquals(ImpactUndetermined.EMPTY, a.undetermined());
    }

    @Test
    @DisplayName("aplicacao JavaScript: os campos nao estao no HTML, entao nao determinado")
    void aplicacaoJavascript() {
        FormSurfaceResult casca = FormSurfaceResult.builder().analyzed(true).jsRendered(true).evidence(List.of()).build();
        ImpactLabelService.Avaliacao a = service.assess(base("https://app.com.br/").formSurface(casca).build());
        assertNull(a.level());
        assertEquals(ImpactUndetermined.JS_RENDERED, a.undetermined());
    }

    @Test
    @DisplayName("status fora de 2xx manda, mesmo que algum campo tenha sido lido")
    void statusVemPrimeiro() {
        // Um desafio de bot com captcha tem campo — e nao e a pagina.
        ScanResult r = base("https://loja.com.br/").httpStatus(403)
                .formSurface(pagina(true, false, true, false)).build();
        assertEquals(ImpactUndetermined.HTTP_STATUS, service.assess(r).undetermined());
        assertNull(service.derive(r));
    }

    @Test
    @DisplayName("resultado nulo nao quebra: nao determinado")
    void nuloNaoQuebra() {
        assertNull(service.derive(null));
        assertEquals(ImpactUndetermined.EMPTY, service.assess(null).undetermined());
    }

    // ── Casos reais ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("petz: /checkout/login bloqueado (403, corpo vazio) nao vira PAGAMENTO pelo endereco")
    void casoPetz() {
        ScanResult r = ScanResult.builder()
                .url("https://www.petz.com.br/checkout/login/indexLogado_Loja")
                .httpStatus(403)
                .formSurface(FormSurfaceResult.vazio())
                .build();

        ImpactLabelService.Avaliacao a = service.assess(r);

        assertNull(a.level(), "o scanner nunca viu a pagina — nao pode afirmar nivel");
        assertEquals(ImpactUndetermined.HTTP_STATUS, a.undetermined());
        assertTrue(a.signals().isEmpty());
    }

    @Test
    @DisplayName("sebimoveis: home com busca e cookie de sessao anonimo e VITRINE com indicio, nao CONTA")
    void casoSebimoveis() {
        ScanResult r = base("https://sebimoveis.com.br/")
                .formSurface(pagina(true, false, false, false))
                .cookieIssues(List.of(cookie("sub100_sites_session")))
                .build();

        ImpactLabelService.Avaliacao a = service.assess(r);

        assertEquals(ImpactLevel.SHOWCASE, a.level());
        assertEquals(List.of("COOKIES:sub100_sites_session"), texto(a.indicators()));
    }

    @Test
    @DisplayName("indicios aparecem mesmo quando a pagina nao foi lida")
    void indiciosSemLeitura() {
        ScanResult r = base("https://loja.com.br/").httpStatus(403)
                .formSurface(FormSurfaceResult.vazio())
                .cookieIssues(List.of(cookie("session"))).build();
        assertEquals(List.of("COOKIES:session"), texto(service.assess(r).indicators()));
    }

    // ── Plataforma de loja: aviso, nao nivel ─────────────────────────────────

    @Test
    @DisplayName("home de loja Shopify sem formulario continua VITRINE, com aviso da plataforma")
    void plataformaNaoEleva() {
        ImpactLabelService.Avaliacao a = service.assess(
                base("https://loja.com.br/").techFingerprint(tech("Shopify")).build());

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

    // ── Gravacao ─────────────────────────────────────────────────────────────

    @Test
    @DisplayName("rotular grava nivel, sinal, indicios e plataforma no resultado")
    void rotularGravaTudo() {
        ScanResult r = base("https://loja.com.br/contato")
                .formSurface(pagina(true, false, true, false))
                .jwtSecurity(List.of(JwtSecurityFinding.builder().source("access_token").build()))
                .techFingerprint(tech("VTEX")).build();

        service.rotular(r);

        assertEquals(ImpactLevel.CONTACT, r.getImpact());
        assertEquals(List.of("FORM:pii-field"), texto(r.getImpactSignals()));
        assertEquals(List.of("JWT:access_token"), texto(r.getImpactIndicators()));
        assertEquals("VTEX", r.getManagedPlatform());
        assertNull(r.getImpactUndetermined());
    }

    @Test
    @DisplayName("rotular pagina bloqueada grava o motivo e nenhum nivel")
    void rotularIndeterminado() {
        ScanResult r = base("https://loja.com.br/").httpStatus(403).formSurface(FormSurfaceResult.vazio()).build();

        service.rotular(r);

        assertNull(r.getImpact());
        assertEquals(ImpactUndetermined.HTTP_STATUS, r.getImpactUndetermined());
    }
}
