package com.joao.cyberaudit.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Locale;

@Service
public class DomainProtectionService {

    private static final String OWNERSHIP_TOKEN_PREFIX = "cyberaudit-verify=";

    /** Teto do arquivo de verificação — o conteúdo esperado tem ~50 bytes. */
    private static final int MAX_VERIFICATION_BYTES = 4096;

    private final HttpClient client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(ScannerHttp.CONNECT_TIMEOUT)
            .build();

    /**
     * Segredo do HMAC do token de posse. Cai para o jwt.secret quando não definido —
     * ambos são segredos de servidor com o mesmo ciclo de vida.
     */
    private final byte[] verificationSecret;

    public DomainProtectionService(
            @Value("${domain.verification-secret}") String secret) {
        this.verificationSecret = secret.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Busca /.well-known/cyberaudit.txt no host e confere se o conteúdo é EXATAMENTE
     * o token esperado para aquele host.
     *
     * O host passa pelo SsrfGuard: este método é alcançável sem autenticação
     * (/scan/verify-check) e sem isso faria requisição de saída para qualquer destino.
     * Redirects não são seguidos de propósito — prova de posse tem que vir do próprio
     * host, não de onde ele apontar.
     */
    public boolean isOwnershipVerified(String host) {
        if (host == null || host.isBlank()) return false;
        try {
            SsrfGuard.validateHost(host);

            String url = "https://" + normalizeHost(host) + "/.well-known/cyberaudit.txt";

            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .GET()
                    .timeout(Duration.ofSeconds(5))
                    .header("User-Agent", "CyberAuditVerifier/1.0")
                    .build();

            HttpResponse<String> resp = client.send(
                    req, ScannerHttp.limitedString(MAX_VERIFICATION_BYTES));

            if (resp.statusCode() != 200) return false;

            String body     = resp.body() == null ? "" : resp.body().trim();
            String expected = generateVerificationToken(host);

            // Comparação em tempo constante — o token é um segredo por domínio.
            return MessageDigest.isEqual(
                    body.getBytes(StandardCharsets.UTF_8),
                    expected.getBytes(StandardCharsets.UTF_8));

        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Token de posse do host: HMAC-SHA256(segredo do servidor, host normalizado).
     *
     * A versão anterior derivava o token de UUID.nameUUIDFromBytes (MD5, sem segredo)
     * e a verificação só conferia o prefixo — qualquer conteúdo começando com
     * "cyberaudit-verify=" liberava scan ativo. Agora o valor é imprevisível sem o
     * segredo do servidor e a conferência é por igualdade exata.
     */
    public String generateVerificationToken(String host) {
        return OWNERSHIP_TOKEN_PREFIX + hmac(normalizeHost(host));
    }

    private String hmac(String host) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(verificationSecret, "HmacSHA256"));
            byte[] digest = mac.doFinal(("cyberaudit:" + host).getBytes(StandardCharsets.UTF_8));
            // 32 hex chars (128 bits) — folgado contra adivinhação e curto para copiar/colar.
            return HexFormat.of().formatHex(digest).substring(0, 32);
        } catch (Exception e) {
            throw new IllegalStateException("Falha ao gerar token de verificação de domínio", e);
        }
    }

    private String normalizeHost(String host) {
        String normalized = host.trim().toLowerCase(Locale.ROOT);
        if (normalized.endsWith(".")) normalized = normalized.substring(0, normalized.length() - 1);
        return normalized;
    }
}
