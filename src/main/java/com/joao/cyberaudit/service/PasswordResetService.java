package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.AuditAction;
import com.joao.cyberaudit.model.PasswordResetToken;
import com.joao.cyberaudit.repository.AppUserRepository;
import com.joao.cyberaudit.repository.PasswordResetTokenRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.HexFormat;
import java.util.Optional;

/**
 * Redefinição de senha por link enviado ao e-mail cadastrado.
 *
 * <h2>Decisões de segurança</h2>
 *
 * <b>Não revela se o e-mail existe.</b> {@link #requestReset} responde igual para
 * conta existente e inexistente. Um endpoint público que diferencia os dois vira
 * um verificador de cadastro — dá para descobrir quem é cliente da plataforma
 * testando uma lista de e-mails.
 *
 * <b>O 2FA continua valendo.</b> Redefinir senha não desliga o segundo fator: se
 * desligasse, quem tivesse acesso à caixa de e-mail contornaria o 2FA inteiro
 * pedindo uma redefinição — exatamente o ataque que o 2FA existe para deter.
 *
 * <b>Token de uso único e curto.</b> 30 minutos, invalidado ao ser usado, e cada
 * pedido novo apaga os anteriores.
 *
 * <h2>Limitação conhecida</h2>
 *
 * Sessões abertas ANTES da redefinição continuam válidas até o JWT expirar (24h).
 * Invalidá-las exigiria um carimbo de "senha alterada em" no usuário, conferido
 * pelo filtro a cada requisição — os JWT são stateless e não têm como ser
 * revogados sozinhos. Fica como melhoria separada; implementar pela metade daria
 * uma falsa sensação de revogação, que é pior do que a limitação declarada.
 */
@Service
public class PasswordResetService {

    /** Curto de propósito: é uma chave de conta trafegando por e-mail. */
    private static final int EXPIRY_MINUTES = 30;

    private final PasswordResetTokenRepository tokenRepository;
    private final AppUserRepository            userRepository;
    private final EmailService                 emailService;
    private final PasswordEncoder              passwordEncoder;
    private final AuditService                 auditService;

    private final SecureRandom random = new SecureRandom();

    @Value("${app.base-url:http://localhost:5173}")
    private String appBaseUrl;

    public PasswordResetService(PasswordResetTokenRepository tokenRepository,
                                AppUserRepository userRepository,
                                EmailService emailService,
                                PasswordEncoder passwordEncoder,
                                AuditService auditService) {
        this.tokenRepository = tokenRepository;
        this.userRepository  = userRepository;
        this.emailService    = emailService;
        this.passwordEncoder = passwordEncoder;
        this.auditService    = auditService;
    }

    /**
     * Gera o link e envia por e-mail. Silencioso quanto à existência da conta.
     *
     * A falha de envio também é engolida de propósito: propagá-la diria ao
     * chamador "este e-mail existe, só não consegui mandar" — mesmo vazamento que
     * a resposta uniforme evita. O erro fica no log do servidor.
     */
    @Transactional
    public void requestReset(String rawEmail) {
        if (rawEmail == null || rawEmail.isBlank()) return;
        String email = rawEmail.toLowerCase().trim();

        Optional<AppUser> encontrado = userRepository.findByEmail(email);
        if (encontrado.isEmpty() || !encontrado.get().isActive()) return;

        AppUser user = encontrado.get();

        tokenRepository.deleteByUserId(user.getId());

        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        String token = HexFormat.of().formatHex(bytes);

        tokenRepository.save(PasswordResetToken.builder()
                .userId(user.getId())
                .tokenHash(sha256(token))
                .expiresAt(LocalDateTime.now().plusMinutes(EXPIRY_MINUTES))
                .used(false)
                .createdAt(LocalDateTime.now())
                .build());

        String link = appBaseUrl.replaceAll("/+$", "") + "/redefinir-senha?token=" + token;

        try {
            emailService.sendPasswordResetEmail(user.getEmail(), user.getName(), link, EXPIRY_MINUTES);
        } catch (RuntimeException e) {
            System.err.println("[PasswordReset] Falha ao enviar link para "
                    + user.getEmail() + ": " + e.getMessage());
        }

        auditService.log(null, user.getId(), user.getEmail(), user.getName(),
                AuditAction.PASSWORD_RESET_REQUESTED, null, true);
    }

    /** Consome o token e grava a senha nova. */
    @Transactional
    public void resetPassword(String token, String novaSenha) {
        if (token == null || token.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Link inválido.");
        }
        PasswordPolicy.validate(novaSenha);

        PasswordResetToken prt = tokenRepository.findByTokenHashAndUsedFalse(sha256(token))
                .filter(t -> t.getExpiresAt().isAfter(LocalDateTime.now()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY,
                        "Link inválido ou expirado. Peça uma nova redefinição."));

        AppUser user = userRepository.findById(prt.getUserId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY,
                        "Link inválido ou expirado. Peça uma nova redefinição."));

        user.setPasswordHash(passwordEncoder.encode(novaSenha));
        userRepository.save(user);

        prt.setUsed(true);
        tokenRepository.save(prt);

        auditService.log(null, user.getId(), user.getEmail(), user.getName(),
                AuditAction.PASSWORD_RESET_COMPLETED, null, true);
    }

    private String sha256(String valor) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(valor.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 indisponível na JVM", e);
        }
    }

    @Scheduled(fixedDelay = 3_600_000) // a cada hora
    @Transactional
    public void limparExpirados() {
        tokenRepository.deleteExpired(LocalDateTime.now());
    }
}
