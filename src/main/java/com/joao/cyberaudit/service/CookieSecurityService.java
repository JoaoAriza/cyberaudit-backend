package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.CookieFinding;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

@Service
public class CookieSecurityService {

    public List<CookieFinding> analyze(List<String> rawSetCookies) {
        List<CookieFinding> findings = new ArrayList<>();
        if (rawSetCookies == null || rawSetCookies.isEmpty()) return findings;

        for (String raw : rawSetCookies) {
            CookieFinding f = evaluate(raw);
            if (f != null) findings.add(f);
        }
        return findings;
    }

    private CookieFinding evaluate(String raw) {
        if (raw == null || raw.isBlank()) return null;

        String[] parts = raw.split(";");
        String nameVal = parts[0].trim();
        String name    = nameVal.contains("=") ? nameVal.split("=", 2)[0].trim() : nameVal;
        String lower   = raw.toLowerCase(Locale.ROOT);

        boolean httpOnly = lower.contains("httponly");
        boolean secure   = lower.contains("secure");
        String  sameSite = extractSameSite(lower);

        List<String> problems = new ArrayList<>();
        String risk = "LOW";

        if (!secure) {
            problems.add("sem Secure: trafega em HTTP plain-text");
            risk = escalate(risk, isSessionCookie(name) ? "HIGH" : "MEDIUM");
        }
        if (!httpOnly) {
            problems.add("sem HttpOnly: acessível via document.cookie (amplifica XSS)");
            risk = escalate(risk, isSessionCookie(name) ? "HIGH" : "MEDIUM");
        }
        if ("MISSING".equals(sameSite)) {
            problems.add("sem SameSite: vulnerável a CSRF em browsers antigos");
            risk = escalate(risk, "MEDIUM");
        } else if ("None".equalsIgnoreCase(sameSite) && !secure) {
            problems.add("SameSite=None sem Secure: rejeitado por Chrome/Firefox");
            risk = escalate(risk, "HIGH");
        }

        if (problems.isEmpty()) return null;

        return new CookieFinding(name, httpOnly, secure, sameSite, risk,
                String.join("; ", problems));
    }

    private String extractSameSite(String lower) {
        if (lower.contains("samesite=strict")) return "Strict";
        if (lower.contains("samesite=lax"))    return "Lax";
        if (lower.contains("samesite=none"))   return "None";
        if (lower.contains("samesite"))        return "UNKNOWN";
        return "MISSING";
    }
    
    private boolean isSessionCookie(String name) {
        if (name == null) return false;
        String l = name.toLowerCase(Locale.ROOT);
        return l.contains("session") || l.contains("token") || l.contains("auth")
                || l.contains("jwt") || l.contains("login") || l.contains("sess")
                || l.equals("phpsessid") || l.equals("jsessionid")
                || l.equals("asp.net_sessionid") || l.contains("csrf");
    }

    private String escalate(String current, String candidate) {
        return rankOf(candidate) > rankOf(current) ? candidate : current;
    }

    private int rankOf(String risk) {
        return switch (risk) { case "HIGH" -> 3; case "MEDIUM" -> 2; default -> 1; };
    }
}