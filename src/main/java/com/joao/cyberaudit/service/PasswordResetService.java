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
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;

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
 * <b>As sessões antigas caem junto.</b> A redefinição grava
 * {@code AppUser.passwordChangedAt}, e o {@code JwtAuthFilter} recusa todo token
 * emitido antes desse carimbo. Sem isso a redefinição não expulsava ninguém: quem
 * tivesse tomado a conta continuava dentro dela por até 24h, que é o tempo de vida
 * do JWT — e o dono trocava a senha achando que tinha resolvido.
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
     *
     * <h2>Por que este método NÃO é @Transactional</h2>
     *
     * O e-mail sai da aplicação e não volta. Enviá-lo dentro de uma transação
     * significa que qualquer falha posterior — inclusive uma que o código engole,
     * porque marcar rollback-only não é a mesma coisa que lançar — desfaz a
     * gravação do token e deixa no mundo um link que aponta para nada. Foi
     * exatamente o que aconteceu: o e-mail chegou, a tela deu erro e o link
     * nasceu inválido.
     *
     * Sem transação envolvendo tudo, o token é gravado e confirmado ANTES do
     * envio. Se o e-mail falhar depois, o token existe sem ter sido entregue —
     * inofensivo, expira em 30 minutos. O contrário não é recuperável.
     */
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
        // O carimbo é o que derruba as sessões abertas: o filtro JWT recusa todo
        // token emitido antes dele. Sem isto, trocar a senha não expulsava ninguém.
        user.setPasswordChangedAt(LocalDateTime.now());
        userRepository.save(user);

        prt.setUsed(true);
        tokenRepository.save(prt);

        // Auditoria só DEPOIS do commit. Dentro da transação, uma falha ao gravar
        // o log (constraint, coluna, indisponibilidade) marca a transação como
        // rollback-only mesmo sendo engolida em Java — e derruba a troca de senha
        // que já tinha dado certo. O registro é importante, mas não às custas da
        // operação que ele apenas descreve.
        UUID   userId    = user.getId();
        String userEmail = user.getEmail();
        String userName  = user.getName();
        Runnable registrar = () -> auditService.log(null, userId, userEmail, userName,
                AuditAction.PASSWORD_RESET_COMPLETED, null, true);

        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    registrar.run();
                }
            });
        } else {
            // Sem transação em volta (teste unitário, ou chamada direta): não há
            // commit para esperar, então registra na hora.
            registrar.run();
        }
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
