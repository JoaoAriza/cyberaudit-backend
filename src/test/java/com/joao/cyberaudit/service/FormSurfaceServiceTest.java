package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.FormSurfaceResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * O que a pagina coleta do visitante, lido do HTML.
 *
 * Substitui a pergunta que o inputSurfaceDetected nunca respondeu: ele e
 * hasQueryParams(url), entao uma vitrine com "?utm_source=face" marcava true e
 * uma pagina com formulario de contato sem query marcava false.
 */
class FormSurfaceServiceTest {

    private final FormSurfaceService service = new FormSurfaceService();

    /** Vitrine tipica do Maps: institucional, botao de WhatsApp, nenhum formulario. */
    private static final String VITRINE = """
            <!DOCTYPE html><html><head><title>Acabamentos Silva</title></head>
            <body>
              <h1>Acabamentos Silva</h1>
              <p>Rua das Flores, 120 — Seg a Sex, 8h as 18h</p>
              <a href="https://wa.me/5544999999999">Fale conosco no WhatsApp</a>
            </body></html>
            """;

    @Test
    @DisplayName("vitrine nao coleta nada")
    void vitrine() {
        FormSurfaceResult r = service.analyze(VITRINE);
        assertFalse(r.isHasForm());
        assertFalse(r.isHasPasswordField());
        assertFalse(r.isCollectsPii());
        assertFalse(r.isHasPaymentField());
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
    @DisplayName("campo brasileiro por name conta, mesmo com type=text")
    void campoPorNome() {
        assertTrue(service.analyze("<input type=\"text\" name=\"cpf\">").isCollectsPii());
        assertTrue(service.analyze("<input type='text' id='celular'>").isCollectsPii());
        assertTrue(service.analyze("<input type=\"text\" name=\"cnpj_cliente\">").isCollectsPii());
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
    @DisplayName("campo de cartao e detectado por autocomplete e por CVV")
    void campoDeCartao() {
        assertTrue(service.analyze("<input autocomplete=\"cc-number\" name=\"n\">").isHasPaymentField());
        assertTrue(service.analyze("<label>CVV</label><input name=\"x\">").isHasPaymentField());
        assertTrue(service.analyze("<input name=\"card_number\">").isHasPaymentField());
        assertTrue(service.analyze("<input name=\"numero_cartao\">").isHasPaymentField());
    }

    @Test
    @DisplayName("corpo ausente nao e o mesmo que pagina sem formulario")
    void corpoAusente() {
        assertFalse(service.analyze(null).isHasForm());
        assertFalse(service.analyze("").isHasForm());
        assertTrue(service.analyze(null).getEvidence().isEmpty());
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
