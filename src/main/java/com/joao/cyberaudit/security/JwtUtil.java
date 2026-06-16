package com.joao.cyberaudit.security;

import com.joao.cyberaudit.config.JwtProperties;
import com.joao.cyberaudit.model.AppUser;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtUtil {

    private final SecretKey key;
    private final long expirationMs;

    public JwtUtil(JwtProperties props) {
        this.key          = Keys.hmacShaKeyFor(props.getSecret().getBytes(StandardCharsets.UTF_8));
        this.expirationMs = props.getExpirationMs();
    }

    private static final long PRE_AUTH_EXPIRY_MS = 5 * 60 * 1_000; // 5 minutos

    /** Token completo — dá acesso total à aplicação. */
    public String generateToken(AppUser user) {
        return Jwts.builder()
                .subject(user.getEmail())
                .claim("role",           user.getRole().name())
                .claim("userId",         user.getId().toString())
                .claim("name",           user.getName())
                .claim("twoFactorPending", false)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expirationMs))
                .signWith(key)
                .compact();
    }

    /**
     * Token de pré-autenticação (válido por 5 min).
     * O usuário validou senha mas ainda não completou o 2FA.
     * Só permite acesso aos endpoints /auth/2fa/**.
     */
    public String generatePreAuthToken(AppUser user) {
        return Jwts.builder()
                .subject(user.getEmail())
                .claim("userId",           user.getId().toString())
                .claim("twoFactorPending", true)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + PRE_AUTH_EXPIRY_MS))
                .signWith(key)
                .compact();
    }

    public String extractEmail(String token) {
        return parseClaims(token).getSubject();
    }

    /** Retorna true se o token é um pre-auth (2FA ainda não completado). */
    public boolean isTwoFactorPending(String token) {
        try {
            Object val = parseClaims(token).get("twoFactorPending");
            return Boolean.TRUE.equals(val);
        } catch (Exception e) {
            return false;
        }
    }

    public boolean isValid(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            System.err.println("[JWT] token inválido: " + e.getClass().getSimpleName() + " — " + e.getMessage());
            return false;
        }
    }

    private Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}