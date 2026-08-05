package com.joao.cyberaudit.service;

import dev.samstevens.totp.code.*;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import org.springframework.stereotype.Service;

import java.util.Base64;

@Service
public class TotpService {

    private static final String ISSUER = "CyberAudit";

    private final SecretGenerator secretGenerator = new DefaultSecretGenerator(32);
    private final TimeProvider    timeProvider    = new SystemTimeProvider();
    private final CodeGenerator   codeGenerator   = new DefaultCodeGenerator(HashingAlgorithm.SHA1);
    private final CodeVerifier    codeVerifier    = new DefaultCodeVerifier(codeGenerator, timeProvider);
    private final QrGenerator     qrGenerator     = new ZxingPngQrGenerator();

    /** Gera um novo segredo TOTP base32 (32 chars). */
    public String generateSecret() {
        return secretGenerator.generate();
    }

    /** Retorna a URI otpauth:// (contém o segredo — nunca enviar a terceiros). */
    public String buildQrUri(String secret, String userEmail) {
        return buildQrData(secret, userEmail).getUri();
    }

    /**
     * Renderiza o QR code como data URI PNG, gerado AQUI no servidor.
     *
     * O frontend montava a imagem em `api.qrserver.com/v1/create-qr-code/?data=<otpauth URI>`,
     * o que mandava o **segredo TOTP completo e o e-mail do usuário** para um serviço
     * de terceiros a cada setup de 2FA. Quem observasse aquele tráfego (o serviço, um
     * proxy, um log) passava a gerar os códigos daquele usuário indefinidamente —
     * comprometimento permanente do segundo fator.
     */
    public String buildQrDataUri(String secret, String userEmail) {
        try {
            byte[] png = qrGenerator.generate(buildQrData(secret, userEmail));
            return "data:" + qrGenerator.getImageMimeType() + ";base64,"
                    + Base64.getEncoder().encodeToString(png);
        } catch (QrGenerationException e) {
            throw new IllegalStateException("Falha ao gerar o QR code do TOTP", e);
        }
    }

    private QrData buildQrData(String secret, String userEmail) {
        return new QrData.Builder()
                .label(userEmail)
                .secret(secret)
                .issuer(ISSUER)
                .algorithm(HashingAlgorithm.SHA1)
                .digits(6)
                .period(30)
                .build();
    }

    /**
     * Verifica se o código de 6 dígitos é válido para o segredo dado.
     * Aceita ±1 janela de 30s para compensar desincronismo de relógio.
     */
    public boolean verify(String secret, String code) {
        if (secret == null || code == null) return false;
        return codeVerifier.isValidCode(secret, code.replace(" ", "").trim());
    }
}
