package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.CookieFinding;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

@Service
public class CookieSecurityService {

    private final MessageCatalog catalog;

    public CookieSecurityService(MessageCatalog catalog) {
        this.catalog = catalog;
    }

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

        // Os problemas vêm do catálogo: esta lista é o que aparece dentro do card do
        // cookie na tela e no campo "Issues" do laudo.
        if (!secure) {
            problems.add(catalog.evidence("COOKIE_SEM_SECURE"));
            risk = escalate(risk, isSessionCookie(name) ? "HIGH" : "MEDIUM");
        }
        if (!httpOnly) {
            problems.add(catalog.evidence("COOKIE_SEM_HTTPONLY"));
            risk = escalate(risk, isSessionCookie(name) ? "HIGH" : "MEDIUM");
        }
        if ("MISSING".equals(sameSite)) {
            problems.add(catalog.evidence("COOKIE_SEM_SAMESITE"));
            risk = escalate(risk, "MEDIUM");
        } else if ("None".equalsIgnoreCase(sameSite) && !secure) {
            problems.add(catalog.evidence("COOKIE_SAMESITE_NONE_SEM_SECURE"));
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