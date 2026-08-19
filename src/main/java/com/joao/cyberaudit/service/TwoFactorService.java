package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.OtpCode;
import com.joao.cyberaudit.repository.AppUserRepository;
import com.joao.cyberaudit.repository.OtpCodeRepository;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Service
public class TwoFactorService {

    private static final int OTP_EXPIRY_MINUTES = 10;

    private final TotpService        totpService;
    private final EmailService        emailService;
    private final OtpCodeRepository   otpCodeRepository;
    private final AppUserRepository   userRepository;

    private final SecureRandom random = new SecureRandom();

    public TwoFactorService(TotpService totpService,
                            EmailService emailService,
                            OtpCodeRepository otpCodeRepository,
                            AppUserRepository userRepository) {
        this.totpService      = totpService;
        this.emailService     = emailService;
        this.otpCodeRepository = otpCodeRepository;
        this.userRepository   = userRepository;
    }

    // ── TOTP setup ────────────────────────────────────────────────────────────

    /**
     * Inicia setup TOTP: gera e persiste um segredo provisório.
     * O usuário ainda não está com TOTP ativado — precisa confirmar com um código.
     */
    @Transactional
    public Map<String, String> startTotpSetup(AppUser user) {
        String secret = totpService.generateSecret();
        user.setTotpSecret(secret);
        user.setTotpEnabled(false);   // ainda não confirmado
        userRepository.save(user);

        return Map.of(
                "secret", secret,
                "qrUri",  totpService.buildQrUri(secret, user.getEmail()),
                // QR renderizado no servidor: o segredo não sai da nossa origem.
                "qrImage", totpService.buildQrDataUri(secret, user.getEmail())
        );
    }

    /**
     * Confirma setup TOTP validando o primeiro código.
     * Ativa TOTP para o usuário.
     */
    @Transactional
    public void confirmTotpSetup(AppUser user, String code) {
        if (user.getTotpSecret() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Inicie o setup TOTP antes de confirmar.");
        }
        if (!totpService.verify(user.getTotpSecret(), code)) {
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY,
                    "Código TOTP inválido. Verifique o horário do dispositivo.");
        }
        user.setTotpEnabled(true);
        userRepository.save(user);
    }

    /** Desativa TOTP e remove o segredo. */
    @Transactional
    public void disableTotp(AppUser user) {
        user.setTotpEnabled(false);
        user.setTotpSecret(null);
        userRepository.save(user);
    }

    // ── Email OTP ─────────────────────────────────────────────────────────────

    /**
     * Ativa Email OTP — mas só depois de provar que o e-mail chega.
     *
     * A ordem importa e é o ponto todo deste método. Ativar primeiro e descobrir
     * depois que o SMTP não funciona deixa a conta inacessível: o login passa a
     * exigir um código que nunca chega, e desativar o 2FA exige estar logado.
     * Não há código de backup no sistema, então não existe saída pelo produto.
     *
     * Enviando antes, uma configuração de e-mail quebrada faz a ATIVAÇÃO falhar —
     * que é reversível e acontece com o usuário logado — em vez de trancar a
     * conta. O código enviado aqui é válido: serve como confirmação de que o
     * caminho inteiro funciona.
     */
    @Transactional
    public void enableEmailOtp(AppUser user) {
        sendEmailOtp(user);   // lança EmailDeliveryException se não sair
        user.setEmailOtpEnabled(true);
        userRepository.save(user);
    }

    /** Desativa Email OTP e limpa códigos pendentes. */
    @Transactional
    public void disableEmailOtp(AppUser user) {
        user.setEmailOtpEnabled(false);
        otpCodeRepository.deleteByUserId(user.getId());
        userRepository.save(user);
    }

    /**
     * Gera e envia um código OTP por email.
     * Limpa códigos anteriores do mesmo usuário para evitar acúmulo.
     */
    @Transactional
    public void sendEmailOtp(AppUser user) {
        otpCodeRepository.deleteByUserId(user.getId());

        String code = String.format("%06d", random.nextInt(1_000_000));

        OtpCode otp = OtpCode.builder()
                .userId(user.getId())
                .code(code)
                .expiresAt(LocalDateTime.now().plusMinutes(OTP_EXPIRY_MINUTES))
                .used(false)
                .createdAt(LocalDateTime.now())
                .build();
        otpCodeRepository.save(otp);

        emailService.sendOtpEmail(user.getEmail(), user.getName(), code);
    }

    /**
     * Verifica o código OTP de email.
     * Marca o código como usado após validação.
     */
    @Transactional
    public void verifyEmailOtp(AppUser user, String code) {
        var otp = otpCodeRepository
                .findFirstByUserIdAndCodeAndUsedFalseAndExpiresAtAfterOrderByCreatedAtDesc(
                        user.getId(), code.trim(), LocalDateTime.now())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY,
                        "Código inválido ou expirado."));

        otp.setUsed(true);
        otpCodeRepository.save(otp);
    }

    // ── Verificação durante login ─────────────────────────────────────────────

    /**
     * Verifica o código 2FA durante o fluxo de login.
     * Aceita tanto TOTP quanto Email OTP dependendo do método configurado.
     */
    public void verifyLoginCode(AppUser user, String code, String method) {
        if ("TOTP".equalsIgnoreCase(method)) {
            if (!user.isTotpEnabled()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "TOTP não está ativado para este usuário.");
            }
            if (!totpService.verify(user.getTotpSecret(), code)) {
                throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY,
                        "Código TOTP inválido.");
            }
        } else if ("EMAIL".equalsIgnoreCase(method)) {
            if (!user.isEmailOtpEnabled()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "Email OTP não está ativado para este usuário.");
            }
            verifyEmailOtp(user, code);
        } else {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Método 2FA inválido. Use 'TOTP' ou 'EMAIL'.");
        }
    }

    /** Retorna os métodos 2FA disponíveis para o usuário. */
    public List<String> getMethods(AppUser user) {
        List<String> methods = new java.util.ArrayList<>();
        if (user.isTotpEnabled())      methods.add("TOTP");
        if (user.isEmailOtpEnabled())  methods.add("EMAIL");
        return methods;
    }

    /** Indica se o usuário tem qualquer 2FA ativado. */
    public boolean isEnabled(AppUser user) {
        return user.isTotpEnabled() || user.isEmailOtpEnabled();
    }

    // ── Limpeza automática ────────────────────────────────────────────────────

    @Scheduled(fixedDelay = 3_600_000) // a cada hora
    @Transactional
    public void cleanExpiredOtps() {
        otpCodeRepository.deleteExpired(LocalDateTime.now());
    }
}
