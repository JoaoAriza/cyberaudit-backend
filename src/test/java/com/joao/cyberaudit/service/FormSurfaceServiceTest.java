package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.FormSurfaceResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * O que a pagina coleta do visitante, lido nos CAMPOS do HTML.
 *
 * Substitui a pergunta que o inputSurfaceDetected nunca respondeu: ele e
 * hasQueryParams(url), entao uma vitrine com "?utm_source=face" marcava true e
 * uma pagina com formulario de contato sem query marcava false.
 *
 * A segunda leva de testes (atributo solto, campo oculto, CVV em texto, data-type)
 * veio de producao: a primeira versao olhava o documento inteiro, nao os campos.
 */
class FormSurfaceServiceTest {

    private final FormSurfaceService service = new FormSurfaceService();

    /** Vitrine tipica do Maps: institucional, botao de WhatsApp, nenhum formulario. */
    private static final String VITRINE = """
            <!DOCTYPE html><html><head><title>Acabamentos Silva</title></head>
            <body>
              <h1>Acabamentos Silva</h1>
              <p>Rua das Flores, 120 — Seg a Sex, 8h as 18h</p>
              <a id="whatsapp-float" href="https://wa.me/5544999999999">Fale conosco no WhatsApp</a>
              <div id="footer-email">contato@acabamentos-silva.com.br</div>
            </body></html>
            """;

    @Test
    @DisplayName("vitrine nao coleta nada, mas foi lida")
    void vitrine() {
        FormSurfaceResult r = service.analyze(VITRINE);
        assertTrue(r.isAnalyzed());
        assertFalse(r.isHasForm());
        assertFalse(r.isHasPasswordField());
        assertFalse(r.isHasPaymentField());
        assertFalse(r.isJsRendered());
    }

    @Test
    @DisplayName("id com 'whatsapp' ou 'email' num botao ou div nao e campo de dado pessoal")
    void atributoForaDeCampoNaoConta() {
        // A primeira versao casava name/id em QUALQUER elemento: o botao flutuante de
        // WhatsApp, que toda vitrine tem, virava campo de telefone.
        assertFalse(service.analyze(VITRINE).isCollectsPii());
    }

    @Test
    @DisplayName("formulario de contato conta como coleta de dado pessoal")
    void formularioDeContato() {
        FormSurfaceResult r = service.analyze("""
                <form action="/contato" method="post">
                  <input type="text" name="nome">
                  <input type="email" name="email">
                  <input type="tel" name="telefone">
                  <button>Enviar</button>
                </form>
                """);
        assertTrue(r.isHasForm());
        assertTrue(r.isCollectsPii());
        assertFalse(r.isHasPasswordField());
        assertFalse(r.isHasPaymentField());
    }

    @Test
    @DisplayName("widget de contato sem <form>, enviado por fetch, tambem coleta (caso frrodas)")
    void widgetSemForm() {
        FormSurfaceResult r = service.analyze("""
                <div class="nv-form-row">
                  <input type="text" class="nv-inp" id="nvCtNome" placeholder="Seu nome *">
                  <input type="email" class="nv-inp" id="nvCtEmail" placeholder="E-mail *">
                  <input type="text" class="nv-inp" id="nvCtTel" placeholder="Telefone">
                </div>
                """);
        assertFalse(r.isHasForm());
        assertTrue(r.isCollectsPii());
    }

    @Test
    @DisplayName("campo brasileiro por name, id ou placeholder conta, mesmo com type=text")
    void campoPorNome() {
        assertTrue(service.analyze("<input type=\"text\" name=\"cpf\">").isCollectsPii());
        assertTrue(service.analyze("<input type='text' id='celular'>").isCollectsPii());
        assertTrue(service.analyze("<input type=\"text\" name=\"cnpj_cliente\">").isCollectsPii());
        assertTrue(service.analyze("<input type=\"text\" placeholder=\"Seu WhatsApp\">").isCollectsPii());
    }

    @Test
    @DisplayName("campo oculto chamado email nao e coleta — o visitante nao digita nada nele")
    void campoOcultoNaoConta() {
        assertFalse(service.analyze("<input type=\"hidden\" name=\"email\" value=\"\">").isCollectsPii());
    }

    @Test
    @DisplayName("formulario de busca nao coleta dado pessoal (caso sebimoveis)")
    void buscaNaoColeta() {
        FormSurfaceResult r = service.analyze("""
                <form id="form_pesquisa_codigo" action="/imovel" method="get">
                  <input type="hidden" name="b_negocio" id="b_negocio">
                  <input type="text" id="ref" placeholder="Referência do imóvel">
                  <select name="b_tipo" id="b_tipo"></select>
                </form>
                <input type="search" name="q" placeholder="Buscar">
                """);
        assertTrue(r.isHasForm());
        assertFalse(r.isCollectsPii());
        assertFalse(r.isHasPasswordField());
    }

    @Test
    @DisplayName("campo de senha indica area autenticada")
    void campoDeSenha() {
        FormSurfaceResult r = service.analyze("""
                <form action="/login"><input type="email" name="email">
                <input type="password" name="senha"></form>
                """);
        assertTrue(r.isHasPasswordField());
        assertTrue(r.isHasForm());
    }

    @Test
    @DisplayName("a palavra senha no texto NAO e campo de senha")
    void palavraSoltaNaoConta() {
        FormSurfaceResult r = service.analyze(
                "<p>Esqueceu sua senha? Ligue para a loja. Nunca pedimos password por telefone.</p>");
        assertFalse(r.isHasPasswordField(), "texto falando de senha nao e campo de senha");
    }

    @Test
    @DisplayName("data-type=password nao e type=password")
    void dataTypeNaoEhType() {
        assertFalse(service.analyze("<input data-type=\"password\" type=\"text\" name=\"busca_rapida\">")
                .isHasPasswordField());
    }

    @Test
    @DisplayName("campo de cartao e detectado por autocomplete, rotulo CVV e nome do campo")
    void campoDeCartao() {
        assertTrue(service.analyze("<input autocomplete=\"cc-number\" name=\"n\">").isHasPaymentField());
        assertTrue(service.analyze("<label>CVV</label><input name=\"x\">").isHasPaymentField());
        assertTrue(service.analyze("<input name=\"card_number\">").isHasPaymentField());
        assertTrue(service.analyze("<input name=\"numero_cartao\">").isHasPaymentField());
        assertTrue(service.analyze("<input type=\"tel\" id=\"cardCvv\">").isHasPaymentField());
    }

    @Test
    @DisplayName("CVV num texto de ajuda nao e campo de cartao")
    void cvvEmTextoNaoEhCartao() {
        assertFalse(service.analyze("<p>O CVV fica no verso do cartao.</p><input type=\"text\" name=\"q\">")
                .isHasPaymentField());
    }

    @Test
    @DisplayName("casca de aplicacao JavaScript: sem campo no HTML, e a tela ainda nem existe")
    void cascaDeSpa() {
        FormSurfaceResult r = service.analyze(
                "<html><body><div id=\"root\"></div><script type=\"module\" src=\"/assets/index.js\"></script></body></html>");
        assertTrue(r.isAnalyzed());
        assertTrue(r.isJsRendered());
    }

    @Test
    @DisplayName("pagina com campo no HTML nao e casca, mesmo com uma raiz vazia para widget JS")
    void ssrNaoEhCasca() {
        assertFalse(service.analyze("<div id=\"root\"><form><input type=\"email\"></form></div>").isJsRendered());
        // A raiz vazia sozinha nao basta: o campo renderizado no servidor ja e a
        // resposta, e o nivel sai dele.
        assertFalse(service.analyze(
                "<div id=\"app\"></div><footer><form><input type=\"email\" name=\"news\"></form></footer>")
                .isJsRendered());
    }

    @Test
    @DisplayName("corpo ausente nao e o mesmo que pagina sem formulario")
    void corpoAusente() {
        assertFalse(service.analyze(null).isAnalyzed());
        assertFalse(service.analyze("").isAnalyzed());
        assertTrue(service.analyze(null).getEvidence().isEmpty());
    }

    // ── Caminhos sugeridos ───────────────────────────────────────────────────

    private List<String> areas(FormSurfaceResult r) {
        return r.getLinkedAreas().stream().map(a -> a.getLevel() + " " + a.getUrl()).toList();
    }

    @Test
    @DisplayName("links do mesmo dominio para conta e checkout viram sugestao, com URL absoluta")
    void linksDeContaECheckout() {
        FormSurfaceResult r = service.analyze("""
                <a href="/minha-conta">Minha conta</a>
                <a class="x" href="https://loja.com.br/checkout/?step=1">Finalizar</a>
                <a href="https://outra-loja.com.br/login">Parceiro</a>
                <a href="mailto:contato@loja.com.br">E-mail</a>
                <a href="#login">Abrir modal</a>
                <a data-href="/entrar" href="/produtos">Produtos</a>
                <a href="/minha-conta/">Minha conta de novo</a>
                """, "https://www.loja.com.br/");

        assertEquals(List.of(
                "ACCOUNT https://www.loja.com.br/minha-conta",
                "PAYMENT https://loja.com.br/checkout"), areas(r));
    }

    @Test
    @DisplayName("link para a propria pagina nao e sugestao")
    void propriaPaginaNaoEntra() {
        FormSurfaceResult r = service.analyze("<a href=\"/login\">Entrar</a>", "https://loja.com.br/login/");
        assertTrue(r.getLinkedAreas().isEmpty());
    }

    @Test
    @DisplayName("segmento parecido nao casa: /carta-de-servicos nao e /cart, /contas-a-pagar nao e /conta")
    void segmentoParecidoNaoCasa() {
        FormSurfaceResult r = service.analyze(
                "<a href=\"/carta-de-servicos\">Carta</a><a href=\"/contas-a-pagar\">Boletos</a>",
                "https://prefeitura.com.br/");
        assertTrue(r.getLinkedAreas().isEmpty());
    }

    @Test
    @DisplayName("no maximo quatro sugestoes, na ordem da pagina")
    void tetoDeSugestoes() {
        FormSurfaceResult r = service.analyze("""
                <a href="/login">1</a><a href="/cadastro">2</a><a href="/account">3</a>
                <a href="/cart">4</a><a href="/checkout">5</a><a href="/meus-pedidos">6</a>
                """, "https://loja.com.br/");
        assertEquals(FormSurfaceService.MAX_AREAS, r.getLinkedAreas().size());
        assertEquals("/login", r.getLinkedAreas().get(0).getPath());
    }

    @Test
    @DisplayName("sem a URL da pagina nao ha como resolver link: nenhuma sugestao")
    void semUrlNaoSugere() {
        assertTrue(service.analyze("<a href=\"/login\">Entrar</a>").getLinkedAreas().isEmpty());
    }

    @Test
    @DisplayName("evidencia registra o que casou")
    void evidencia() {
        FormSurfaceResult r = service.analyze(
                "<form><input type=\"password\"><input type=\"email\"></form>");
        assertTrue(r.getEvidence().contains("form"));
        assertTrue(r.getEvidence().contains("password-field"));
        assertTrue(r.getEvidence().contains("pii-field"));
        assertFalse(r.getEvidence().contains("payment-field"));
    }
}
