package com.joao.cyberaudit.controller;

import com.joao.cyberaudit.dto.*;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.Invite;
import com.joao.cyberaudit.repository.AppUserRepository;
import com.joao.cyberaudit.service.AuthService;
import com.joao.cyberaudit.service.GuestRateLimitService;
import com.joao.cyberaudit.service.InviteService;
import com.joao.cyberaudit.service.PlanLimitService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

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

    public AuthController(AuthService authService,
                          GuestRateLimitService guestRateLimitService,
                          InviteService inviteService,
                          PlanLimitService planLimitService,
                          AppUserRepository userRepository) {
        this.authService           = authService;
        this.guestRateLimitService = guestRateLimitService;
        this.inviteService         = inviteService;
        this.planLimitService      = planLimitService;
        this.userRepository        = userRepository;
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
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest req) {
        return ResponseEntity.ok(authService.login(req));
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