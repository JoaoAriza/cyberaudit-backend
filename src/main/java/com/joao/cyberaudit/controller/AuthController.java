package com.joao.cyberaudit.controller;

import com.joao.cyberaudit.dto.*;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.AuditAction;
import com.joao.cyberaudit.model.Invite;
import com.joao.cyberaudit.repository.AppUserRepository;
import com.joao.cyberaudit.security.JwtUtil;
import com.joao.cyberaudit.service.*;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDate;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final InviteService         inviteService;
    private final AuthService           authService;
    private final GuestRateLimitService guestRateLimitService;
    private final PlanLimitService      planLimitService;
    private final AppUserRepository     userRepository;
    private final TwoFactorService      twoFactorService;
    private final JwtUtil               jwtUtil;
    private final AuditService          auditService;
    private final AuthThrottleService   authThrottleService;

    public AuthController(AuthService authService,
                          GuestRateLimitService guestRateLimitService,
                          InviteService inviteService,
                          PlanLimitService planLimitService,
                          AppUserRepository userRepository,
                          TwoFactorService twoFactorService,
                          JwtUtil jwtUtil,
                          AuditService auditService,
                          AuthThrottleService authThrottleService) {
        this.authService           = authService;
        this.guestRateLimitService = guestRateLimitService;
        this.inviteService         = inviteService;
        this.planLimitService      = planLimitService;
        this.userRepository        = userRepository;
        this.twoFactorService      = twoFactorService;
        this.jwtUtil               = jwtUtil;
        this.auditService          = auditService;
        this.authThrottleService   = authThrottleService;
    }

    /**
     * Retorna se o sistema já foi configurado (primeiro usuário criado).
     * Público — usado pelo frontend para exibir wizard de setup na primeira instalação.
     */
    @GetMapping("/setup-status")
    public ResponseEntity<Map<String, Object>> setupStatus() {
        boolean configured = userRepository.count() > 0;
        return ResponseEntity.ok(Map.of("configured", configured));
    }

    @PostMapping("/setup")
    public ResponseEntity<AuthResponse> setup(@RequestBody SetupRequest req) {
        return ResponseEntity.ok(authService.setup(req));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest req,
                                              HttpServletRequest request) {
        return ResponseEntity.ok(authService.login(req, request.getRemoteAddr()));
    }

    /**
     * Auto-registro público: cria conta FREE + usuário OWNER e retorna JWT.
     * Não requer autenticação prévia.
     */
    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@RequestBody RegisterRequest req) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.register(req));
    }

    @GetMapping("/me")
    public ResponseEntity<?> me() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()
                || auth.getPrincipal() instanceof String) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Token inválido ou expirado."));
        }
        AppUser u = (AppUser) auth.getPrincipal();
        return ResponseEntity.ok(UserDto.from(u, planLimitService));
    }

    @GetMapping("/guest-status")
    public ResponseEntity<Map<String, Object>> guestStatus(HttpServletRequest request) {
        String ip         = request.getRemoteAddr();
        int    remaining  = guestRateLimitService.getRemainingScans(ip);
        int    dailyLimit = GuestRateLimitService.DAILY_LIMIT;
        int    used       = dailyLimit - remaining;
        return ResponseEntity.ok(Map.of(
                "ip",            ip,
                "used",          used,
                "remaining",     remaining,
                "dailyLimit",    dailyLimit,
                "resetsAt",      LocalDate.now().plusDays(1).atStartOfDay().toString(),
                "authenticated", false
        ));
    }

    // ── 2FA Setup (requer token válido — não pre-auth) ────────────────────────

    /** Inicia setup TOTP: gera secret provisório, retorna {secret, qrUri}. */
    @PostMapping("/2fa/setup/totp")
    public ResponseEntity<Map<String, String>> startTotpSetup() {
        AppUser user = currentUser();
        return ResponseEntity.ok(twoFactorService.startTotpSetup(user));
    }

    /** Confirma setup TOTP com o código do authenticator. */
    @PostMapping("/2fa/setup/totp/confirm")
    public ResponseEntity<Map<String, String>> confirmTotpSetup(
            @RequestBody Map<String, String> body) {
        AppUser user = currentUser();
        twoFactorService.confirmTotpSetup(user, body.get("code"));
        auditService.log(user, AuditAction.TOTP_ENABLED, null);
        return ResponseEntity.ok(Map.of("message", "TOTP ativado com sucesso."));
    }

    /** Desativa TOTP. */
    @DeleteMapping("/2fa/totp")
    public ResponseEntity<Map<String, String>> disableTotp() {
        AppUser user = currentUser();
        twoFactorService.disableTotp(user);
        auditService.log(user, AuditAction.TOTP_DISABLED, null);
        return ResponseEntity.ok(Map.of("message", "TOTP desativado."));
    }

    /** Ativa Email OTP. */
    @PostMapping("/2fa/email")
    public ResponseEntity<Map<String, String>> enableEmailOtp() {
        AppUser user = currentUser();
        twoFactorService.enableEmailOtp(user);
        auditService.log(user, AuditAction.EMAIL_OTP_ENABLED, null);
        return ResponseEntity.ok(Map.of("message", "Email OTP ativado."));
    }

    /** Desativa Email OTP. */
    @DeleteMapping("/2fa/email")
    public ResponseEntity<Map<String, String>> disableEmailOtp() {
        AppUser user = currentUser();
        twoFactorService.disableEmailOtp(user);
        auditService.log(user, AuditAction.EMAIL_OTP_DISABLED, null);
        return ResponseEntity.ok(Map.of("message", "Email OTP desativado."));
    }

    // ── 2FA Login (requer pre-auth token) ─────────────────────────────────────

    /**
     * Verifica o código 2FA durante o login.
     * Aceita pre-auth token (twoFactorPending=true).
     * Retorna token completo em caso de sucesso.
     */
    @PostMapping("/2fa/verify")
    public ResponseEntity<AuthResponse> verify2fa(
            @RequestBody Map<String, String> body,
            HttpServletRequest request) {
        AppUser user = currentUser();
        String  code   = body.get("code");
        String  method = body.getOrDefault("method", "TOTP");

        // Sem isto o código de 6 dígitos é força-brutável: o token pre-auth pode ser
        // reemitido à vontade e o OTP de e-mail vale 10 minutos.
        authThrottleService.checkTwoFactorAllowed(user.getId());
        try {
            twoFactorService.verifyLoginCode(user, code, method);
        } catch (RuntimeException e) {
            authThrottleService.recordTwoFactorFailure(user.getId());
            throw e;
        }
        authThrottleService.recordTwoFactorSuccess(user.getId());

        auditService.log(user, AuditAction.LOGIN_2FA_VERIFIED, "method=" + method);
        auditService.log(user, AuditAction.LOGIN_SUCCESS, "via 2FA (" + method + ")");
        String fullToken = jwtUtil.generateToken(user);
        return ResponseEntity.ok(new AuthResponse(fullToken, UserDto.from(user, planLimitService)));
    }

    /**
     * Reenvia OTP por email durante o login (aceita pre-auth token).
     */
    @PostMapping("/2fa/send-email-otp")
    public ResponseEntity<Map<String, String>> resendEmailOtp() {
        AppUser user = currentUser();
        if (!user.isEmailOtpEnabled()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Email OTP não está habilitado para este usuário.");
        }
        // Cooldown: o endpoint aceita token pre-auth, então quem só tem a senha
        // poderia usá-lo como bomba de e-mail contra a vítima.
        authThrottleService.checkOtpResendAllowed(user.getId());
        twoFactorService.sendEmailOtp(user);
        authThrottleService.recordOtpSent(user.getId());
        return ResponseEntity.ok(Map.of("message", "Código reenviado para " + user.getEmail()));
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private AppUser currentUser() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !(auth.getPrincipal() instanceof AppUser u)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Não autenticado.");
        }
        return u;
    }

    @PostMapping("/accept-invite/{token}")
    public ResponseEntity<Map<String, String>> acceptInvite(
            @PathVariable String token,
            @RequestBody InviteAcceptRequest req) {
        inviteService.accept(token, req);
        return ResponseEntity.ok(Map.of(
                "message",  "Conta criada com sucesso. Faça login para continuar.",
                "loginUrl", "/auth/login"
        ));
    }
}