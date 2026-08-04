package com.joao.cyberaudit.service;

import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Lockout de tentativas de autenticação.
 *
 * Antes: `/auth/login` e `/auth/2fa/verify` aceitavam tentativas ilimitadas —
 * `LOGIN_FAILED` ia para o audit log e nada mais acontecia. Senha e código de 6
 * dígitos eram força-brutáveis; o OTP de e-mail vive 10 minutos, o que dá tempo
 * de sobra para varrer boa parte do espaço de 1.000.000 de códigos.
 *
 * Contagem em memória, como o resto dos limitadores do app (RateLimitService,
 * GuestRateLimitService). Em deploy multi-instância cada nó conta o seu — ainda
 * assim reduz o teto de tentativas por ordens de magnitude.
 *
 * Trade-off aceito: contar por conta permite que um atacante bloqueie o login de
 * uma vítima por 15 minutos. Por isso a janela é curta e o contador zera em
 * qualquer sucesso.
 */
@Service
public class AuthThrottleService {

    private static final int      MAX_LOGIN_FAILURES = 5;
    private static final Duration LOGIN_LOCKOUT      = Duration.ofMinutes(15);

    /** Por IP o teto é mais alto: um NAT corporativo inteiro pode sair do mesmo IP. */
    private static final int      MAX_LOGIN_FAILURES_PER_IP = 20;
    private static final Duration IP_LOCKOUT                = Duration.ofMinutes(15);

    private static final int      MAX_TWO_FACTOR_FAILURES = 5;
    private static final Duration TWO_FACTOR_LOCKOUT      = Duration.ofMinutes(15);

    /** Intervalo mínimo entre reenvios de OTP — evita usar o app como bomba de e-mail. */
    private static final Duration OTP_RESEND_COOLDOWN = Duration.ofSeconds(60);

    /** Entradas sem atividade além disso são descartadas na limpeza periódica. */
    private static final Duration ENTRY_TTL = Duration.ofHours(2);

    private static final class Attempts {
        int     failures;
        Instant lockedUntil;
        Instant lastActivity = Instant.now();
    }

    private final ConcurrentHashMap<String, Attempts> attempts   = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Instant>  lastOtpSend = new ConcurrentHashMap<>();

    // ── Login ────────────────────────────────────────────────────────────────

    /** Chamar ANTES de validar a senha. Lança 429 se conta ou IP estiverem travados. */
    public void checkLoginAllowed(String email, String ip) {
        assertNotLocked(loginKey(email), "Muitas tentativas de login para esta conta.");
        assertNotLocked(ipKey(ip),       "Muitas tentativas de login a partir deste endereço.");
    }

    public void recordLoginFailure(String email, String ip) {
        registerFailure(loginKey(email), MAX_LOGIN_FAILURES,        LOGIN_LOCKOUT);
        registerFailure(ipKey(ip),       MAX_LOGIN_FAILURES_PER_IP, IP_LOCKOUT);
    }

    public void recordLoginSuccess(String email, String ip) {
        attempts.remove(loginKey(email));
        attempts.remove(ipKey(ip));
    }

    // ── 2FA ──────────────────────────────────────────────────────────────────

    /**
     * Chamar ANTES de validar o código 2FA. Sem isso, o token pre-auth (5 min)
     * podia ser reemitido indefinidamente e o código de 6 dígitos, varrido.
     */
    public void checkTwoFactorAllowed(Object userId) {
        assertNotLocked(twoFactorKey(userId),
                "Muitas tentativas de verificação 2FA. Aguarde antes de tentar de novo.");
    }

    public void recordTwoFactorFailure(Object userId) {
        registerFailure(twoFactorKey(userId), MAX_TWO_FACTOR_FAILURES, TWO_FACTOR_LOCKOUT);
    }

    public void recordTwoFactorSuccess(Object userId) {
        attempts.remove(twoFactorKey(userId));
    }

    // ── Reenvio de OTP ───────────────────────────────────────────────────────

    /** Lança 429 se o último envio foi há menos de {@link #OTP_RESEND_COOLDOWN}. */
    public void checkOtpResendAllowed(Object userId) {
        Instant last = lastOtpSend.get(String.valueOf(userId));
        if (last == null) return;

        Duration since = Duration.between(last, Instant.now());
        if (since.compareTo(OTP_RESEND_COOLDOWN) < 0) {
            long wait = OTP_RESEND_COOLDOWN.minus(since).toSeconds() + 1;
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,
                    "Aguarde " + wait + "s para solicitar um novo código.");
        }
    }

    public void recordOtpSent(Object userId) {
        lastOtpSend.put(String.valueOf(userId), Instant.now());
    }

    // ── Interno ──────────────────────────────────────────────────────────────

    private void assertNotLocked(String key, String message) {
        Attempts entry = attempts.get(key);
        if (entry == null || entry.lockedUntil == null) return;

        synchronized (entry) {
            if (entry.lockedUntil == null) return;
            if (Instant.now().isBefore(entry.lockedUntil)) {
                long wait = Duration.between(Instant.now(), entry.lockedUntil).toMinutes() + 1;
                throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,
                        message + " Tente novamente em " + wait + " minuto(s).");
            }
            // Lockout expirou — zera para o usuário legítimo recomeçar do zero.
            entry.failures    = 0;
            entry.lockedUntil = null;
        }
    }

    private void registerFailure(String key, int maxFailures, Duration lockout) {
        Attempts entry = attempts.computeIfAbsent(key, k -> new Attempts());
        synchronized (entry) {
            entry.lastActivity = Instant.now();
            entry.failures++;
            if (entry.failures >= maxFailures) {
                entry.lockedUntil = Instant.now().plus(lockout);
            }
        }
    }

    private String loginKey(String email) {
        return "login:" + (email == null ? "" : email.trim().toLowerCase(Locale.ROOT));
    }

    private String ipKey(String ip) {
        return "ip:" + (ip == null ? "desconhecido" : ip);
    }

    private String twoFactorKey(Object userId) {
        return "2fa:" + userId;
    }

    @Scheduled(fixedDelay = 1_800_000) // a cada 30 min
    public void cleanUp() {
        Instant cutoff = Instant.now().minus(ENTRY_TTL);
        attempts.entrySet().removeIf(e -> {
            Attempts a = e.getValue();
            synchronized (a) {
                boolean locked = a.lockedUntil != null && Instant.now().isBefore(a.lockedUntil);
                return !locked && a.lastActivity.isBefore(cutoff);
            }
        });
        lastOtpSend.entrySet().removeIf(e -> e.getValue().isBefore(cutoff));
    }
}
