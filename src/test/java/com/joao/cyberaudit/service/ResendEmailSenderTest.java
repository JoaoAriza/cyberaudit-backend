package com.joao.cyberaudit.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.joao.cyberaudit.exception.EmailDeliveryException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Transporte pelo Resend.
 *
 * Não há chamada de rede aqui: o que dá para cobrir sem provedor de verdade é a
 * validação de configuração e o resumo do corpo de erro — que é justamente o que
 * torna a falha diagnosticável no log. A entrega em si só o ambiente real prova.
 */
class ResendEmailSenderTest {

    private ResendEmailSender sender(String apiKey) {
        ResendEmailSender s = new ResendEmailSender(new ObjectMapper());
        ReflectionTestUtils.setField(s, "apiKey", apiKey);
        return s;
    }

    @Test
    @DisplayName("sem RESEND_API_KEY falha na hora, com mensagem que aponta a variável")
    void semChaveFalhaExplicito() {
        var erro = assertThrows(EmailDeliveryException.class,
                () -> sender("").send("a@b.com", "c@d.com", "assunto", "<p>oi</p>"));

        assertTrue(erro.getMessage().contains("RESEND_API_KEY"),
                "a mensagem precisa dizer o que configurar: " + erro.getMessage());
    }

    @Test
    @DisplayName("chave nula é tratada como ausente, não como NullPointerException")
    void chaveNulaNaoExplode() {
        assertThrows(EmailDeliveryException.class,
                () -> sender(null).send("a@b.com", "c@d.com", "assunto", "<p>oi</p>"));
    }

    @Test
    @DisplayName("corpo de erro longo é truncado — não polui o log")
    void resumoTrunca() {
        String longo = "x".repeat(500);
        String out = (String) ReflectionTestUtils.invokeMethod(sender("k"), "resumo", longo);

        assertEquals(301, out.length(), "300 caracteres + reticências");
        assertTrue(out.endsWith("…"));
    }

    @Test
    @DisplayName("corpo vazio vira marcador legível em vez de string vazia no log")
    void resumoDeCorpoVazio() {
        assertEquals("(sem corpo)",
                ReflectionTestUtils.invokeMethod(sender("k"), "resumo", ""));
        assertEquals("(sem corpo)",
                ReflectionTestUtils.invokeMethod(sender("k"), "resumo", (Object) null));
    }
}
