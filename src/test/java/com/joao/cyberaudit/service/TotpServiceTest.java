package com.joao.cyberaudit.service;

import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.HashingAlgorithm;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
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

    // ── Janela que casou (base do consumo do código, BUG-04) ────────────────

    /** 1_000_000_020 s cai na janela 33_333_334 (de 30 s) — longe da borda. */
    private static final long AGORA_S = 1_000_000_020L;
    private static final long JANELA  = AGORA_S / 30;

    private final TotpService comRelogioFixo = new TotpService(() -> AGORA_S);
    private final DefaultCodeGenerator gerador = new DefaultCodeGenerator(HashingAlgorithm.SHA1);

    @Test
    @DisplayName("devolve a janela em que o código casou: a atual e uma para cada lado")
    void devolveAJanelaQueCasou() throws Exception {
        String secret = service.generateSecret();

        assertEquals(JANELA,     comRelogioFixo.matchingTimeStep(secret, gerador.generate(secret, JANELA)));
        assertEquals(JANELA - 1, comRelogioFixo.matchingTimeStep(secret, gerador.generate(secret, JANELA - 1)));
        assertEquals(JANELA + 1, comRelogioFixo.matchingTimeStep(secret, gerador.generate(secret, JANELA + 1)));
    }

    @Test
    @DisplayName("fora da tolerância de ±1 janela, ou código errado: -1")
    void foraDaToleranciaNaoCasa() throws Exception {
        String secret = service.generateSecret();

        assertEquals(-1, comRelogioFixo.matchingTimeStep(secret, gerador.generate(secret, JANELA - 2)));
        assertEquals(-1, comRelogioFixo.matchingTimeStep(secret, gerador.generate(secret, JANELA + 2)));
        assertEquals(-1, comRelogioFixo.matchingTimeStep(secret, "000000".equals(gerador.generate(secret, JANELA))
                ? "111111" : "000000"));
        assertEquals(-1, comRelogioFixo.matchingTimeStep(null, "123456"));
        assertEquals(-1, comRelogioFixo.matchingTimeStep(secret, null));
    }

    @Test
    @DisplayName("espaço no meio do código (como o app mostra, \"123 456\") ainda casa")
    void aceitaCodigoComEspaco() throws Exception {
        String secret = service.generateSecret();
        String codigo = gerador.generate(secret, JANELA);

        assertEquals(JANELA, comRelogioFixo.matchingTimeStep(secret,
                codigo.substring(0, 3) + " " + codigo.substring(3)));
    }
}
