package com.joao.cyberaudit.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {

    private String secret = "change-this-secret-in-production-min-32chars!!";

    private long expirationMs = 86_400_000L;

    public String getSecret()             { return secret; }
    public void setSecret(String s)       { this.secret = s; }
    public long getExpirationMs()         { return expirationMs; }
    public void setExpirationMs(long ms)  { this.expirationMs = ms; }
}