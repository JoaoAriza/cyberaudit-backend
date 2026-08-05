package com.joao.cyberaudit.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TotpServiceTest {

    private final TotpService service = new TotpService();

    @Test
    @DisplayName("QR é renderizado localmente como data URI PNG — sem serviço externo")
    void qrEDataUriLocal() {
        String secret = service.generateSecret();

        String qr = service.buildQrDataUri(secret, "usuario@example.com");

        assertTrue(qr.startsWith("data:image/png;base64,"), qr.substring(0, Math.min(40, qr.length())));
        assertFalse(qr.contains("http"), "o QR não pode referenciar nenhuma URL externa");

        byte[] png = Base64.getDecoder().decode(qr.substring("data:image/png;base64,".length()));
        assertTrue(png.length > 100, "PNG vazio ou truncado");
        // Assinatura PNG: \x89 P N G
        assertTrue((png[0] & 0xFF) == 0x89 && png[1] == 'P' && png[2] == 'N' && png[3] == 'G',
                "conteúdo não é um PNG válido");
    }

    @Test
    @DisplayName("o segredo não aparece no data URI em texto claro")
    void segredoNaoVazaNoDataUri() {
        String secret = service.generateSecret();

        String qr = service.buildQrDataUri(secret, "usuario@example.com");

        assertFalse(qr.contains(secret),
                "o segredo estaria legível para qualquer coisa que logue a resposta");
    }

    @Test
    @DisplayName("a URI otpauth continua válida para entrada manual")
    void otpauthUriContinuaValida() {
        String secret = service.generateSecret();

        String uri = service.buildQrUri(secret, "usuario@example.com");

        assertTrue(uri.startsWith("otpauth://totp/"), uri);
        assertTrue(uri.contains("secret=" + secret));
        assertTrue(uri.contains("issuer=CyberAudit"));
    }

    @Test
    @DisplayName("cada setup gera um segredo diferente")
    void segredosSaoUnicos() {
        assertNotEquals(service.generateSecret(), service.generateSecret());
    }

    @Test
    @DisplayName("verify rejeita código nulo, vazio e errado")
    void verifyRejeitaInvalidos() {
        String secret = service.generateSecret();

        assertFalse(service.verify(secret, null));
        assertFalse(service.verify(null, "123456"));
        assertFalse(service.verify(secret, "000000"));
        assertFalse(service.verify(secret, "nao-numerico"));
    }
}
