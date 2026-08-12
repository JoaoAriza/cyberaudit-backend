package com.joao.cyberaudit.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {

    /**
     * SEM valor padrão de propósito.
     *
     * Havia aqui um default fixo ("change-this-secret-in-production-min-32chars!!"),
     * uma string pública no código-fonte. Hoje ele é inalcançável porque o
     * application.properties define `jwt.secret=${JWT_SECRET}` sem fallback — mas
     * bastaria alguém mexer nessa linha para que um deploy sem JWT_SECRET subisse
     * assinando tokens com um segredo que qualquer pessoa lê no repositório, e
     * portanto forjável por qualquer um. Falhar no boot é o comportamento correto.
     */
    private String secret;

    private long expirationMs = 86_400_000L;

    public String getSecret()             { return secret; }
    public void setSecret(String s)       { this.secret = s; }
    public long getExpirationMs()         { return expirationMs; }
    public void setExpirationMs(long ms)  { this.expirationMs = ms; }
}