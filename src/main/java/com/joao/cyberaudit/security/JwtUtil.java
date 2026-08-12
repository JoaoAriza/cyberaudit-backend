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

    /** HMAC-SHA256 exige 256 bits. Abaixo disso o JJWT recusa a chave. */
    private static final int MIN_SECRET_BYTES = 32;

    public JwtUtil(JwtProperties props) {
        this.key          = buildKey(props.getSecret());
        this.expirationMs = props.getExpirationMs();
    }

    /**
     * Valida o segredo com mensagem explícita.
     *
     * Sem isto, segredo ausente virava NullPointerException e segredo curto virava
     * WeakKeyException — as duas aparecendo no log apenas como "Error creating bean
     * with name 'jwtUtil': Constructor threw exception", sem dizer QUAL variável
     * está errada nem por quê. Num deploy em PaaS, onde não se edita arquivo para
     * depurar, isso custa muito tempo.
     */
    private static SecretKey buildKey(String secret) {
        if (secret == null || secret.isBlank()) {
            throw new IllegalStateException(
                    "JWT_SECRET não está definido (ou está vazio). Defina a variável de "
                            + "ambiente com no mínimo " + MIN_SECRET_BYTES + " caracteres. "
                            + "Gere um valor com: openssl rand -hex 32");
        }

        byte[] bytes = secret.getBytes(StandardCharsets.UTF_8);
        if (bytes.length < MIN_SECRET_BYTES) {
            throw new IllegalStateException(
                    "JWT_SECRET tem apenas " + bytes.length + " bytes; o mínimo é "
                            + MIN_SECRET_BYTES + " (HMAC-SHA256 exige 256 bits). "
                            + "Gere um valor com: openssl rand -hex 32");
        }

        return Keys.hmacShaKeyFor(bytes);
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