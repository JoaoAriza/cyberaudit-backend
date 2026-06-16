package com.joao.cyberaudit.service;

import dev.samstevens.totp.code.*;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import org.springframework.stereotype.Service;

@Service
public class TotpService {

    private static final String ISSUER = "CyberAudit";

    private final SecretGenerator secretGenerator = new DefaultSecretGenerator(32);
    private final TimeProvider    timeProvider    = new SystemTimeProvider();
    private final CodeGenerator   codeGenerator   = new DefaultCodeGenerator(HashingAlgorithm.SHA1);
    private final CodeVerifier    codeVerifier    = new DefaultCodeVerifier(codeGenerator, timeProvider);

    /** Gera um novo segredo TOTP base32 (32 chars). */
    public String generateSecret() {
        return secretGenerator.generate();
    }

    /**
     * Retorna a URI otpauth:// para exibição como QR code.
     * No frontend, transformar em QR via api.qrserver.com ou similar.
     */
    public String buildQrUri(String secret, String userEmail) {
        QrData data = new QrData.Builder()
                .label(userEmail)
                .secret(secret)
                .issuer(ISSUER)
                .algorithm(HashingAlgorithm.SHA1)
                .digits(6)
                .period(30)
                .build();
        return data.getUri();
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
