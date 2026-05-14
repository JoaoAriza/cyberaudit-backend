package com.joao.cyberaudit.controller;

import com.joao.cyberaudit.dto.*;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.service.AuthService;
import com.joao.cyberaudit.service.GuestRateLimitService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService          authService;
    private final GuestRateLimitService guestRateLimitService;

    public AuthController(AuthService authService,
                          GuestRateLimitService guestRateLimitService) {
        this.authService          = authService;
        this.guestRateLimitService = guestRateLimitService;
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
    public ResponseEntity<UserDto> me(@AuthenticationPrincipal AppUser user) {
        UserDto dto = UserDto.from(user);
        dto.setRemainingScans(null);
        dto.setDailyLimit(null);
        return ResponseEntity.ok(dto);
    }

    @GetMapping("/guest-status")
    public ResponseEntity<Map<String, Object>> guestStatus(HttpServletRequest request) {
        String ip           = request.getRemoteAddr();
        int    remaining    = guestRateLimitService.getRemainingScans(ip);
        int    dailyLimit   = GuestRateLimitService.DAILY_LIMIT;
        int    used         = dailyLimit - remaining;

        return ResponseEntity.ok(Map.of(
                "ip",            ip,
                "used",          used,
                "remaining",     remaining,
                "dailyLimit",    dailyLimit,
                "resetsAt",      LocalDate.now().plusDays(1)
                        .atStartOfDay().toString(),
                "authenticated", false
        ));
    }
}