package com.joao.cyberaudit.service;

import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class HeaderService {

    private static final Pattern MAX_AGE_PATTERN =
            Pattern.compile("max-age=(\\d+)", Pattern.CASE_INSENSITIVE);

    public Map<String, String> analyzeSecurityHeaders(Map<String, String> h) {
        Map<String, String> result = new HashMap<>();
        analyzeXFrame(h, result);
        analyzeContentType(h, result);
        analyzeHsts(h, result);
        analyzeCsp(h, result);
        analyzeReferrerPolicy(h, result);
        analyzePermissionsPolicy(h, result);
        return result;
    }
    
    public boolean detectsServerVersionExposure(Map<String, String> h) {
        String server  = h.getOrDefault("server", "");
        String xPowered = h.getOrDefault("x-powered-by", "");
        return (!server.isBlank() && containsVersion(server)) || !xPowered.isBlank();
    }


    private void analyzeXFrame(Map<String, String> h, Map<String, String> out) {
        String v = h.get("x-frame-options");
        if (v == null)                          out.put("X-Frame-Options", "MISSING");
        else if (v.equalsIgnoreCase("DENY"))    out.put("X-Frame-Options", "OK (DENY)");
        else if (v.equalsIgnoreCase("SAMEORIGIN")) out.put("X-Frame-Options", "OK (SAMEORIGIN)");
        else                                    out.put("X-Frame-Options", "UNKNOWN (" + v + ")");
    }

    private void analyzeContentType(Map<String, String> h, Map<String, String> out) {
        String v = h.get("x-content-type-options");
        if (v == null)                        out.put("X-Content-Type-Options", "MISSING");
        else if (v.equalsIgnoreCase("nosniff")) out.put("X-Content-Type-Options", "OK (nosniff)");
        else                                   out.put("X-Content-Type-Options", "WEAK (" + v + ")");
    }

    private void analyzeHsts(Map<String, String> h, Map<String, String> out) {
        String v = h.get("strict-transport-security");
        if (v == null) { out.put("Strict-Transport-Security", "MISSING"); return; }

        Matcher m = MAX_AGE_PATTERN.matcher(v);
        if (!m.find()) { out.put("Strict-Transport-Security", "WEAK (sem max-age)"); return; }

        long maxAge = Long.parseLong(m.group(1));
        if (maxAge == 0) {
            out.put("Strict-Transport-Security", "WEAK (max-age=0 deletes HSTS)");
        } else if (maxAge < 2_592_000) {
            out.put("Strict-Transport-Security", "WEAK (max-age muito curto: " + maxAge + "s)");
        } else {
            out.put("Strict-Transport-Security", "OK (" + v + ")");
        }
    }

    private void analyzeCsp(Map<String, String> h, Map<String, String> out) {
        String v = h.get("content-security-policy");
        if (v == null) { out.put("Content-Security-Policy", "MISSING"); return; }

        String lower = v.toLowerCase(Locale.ROOT);
        if (lower.contains("'unsafe-inline'") || lower.contains("'unsafe-eval'"))
            out.put("Content-Security-Policy", "WEAK (unsafe-inline ou unsafe-eval presente)");
        else if (lower.contains("default-src") || lower.contains("script-src"))
            out.put("Content-Security-Policy", "OK");
        else
            out.put("Content-Security-Policy", "WEAK (" + v + ")");
    }

    private void analyzeReferrerPolicy(Map<String, String> h, Map<String, String> out) {
        String v = h.get("referrer-policy");
        if (v == null) { out.put("Referrer-Policy", "MISSING"); return; }

        String lower = v.toLowerCase(Locale.ROOT);
        if (lower.equals("unsafe-url") || lower.equals("no-referrer-when-downgrade"))
            out.put("Referrer-Policy", "WEAK (" + v + ")");
        else
            out.put("Referrer-Policy", "OK (" + v + ")");
    }

    private void analyzePermissionsPolicy(Map<String, String> h, Map<String, String> out) {
        String v = h.get("permissions-policy");
        if (v == null) v = h.get("feature-policy");
        out.put("Permissions-Policy", v == null ? "MISSING" : "OK");
    }

    private boolean containsVersion(String value) {
        return value.matches(".*[/\\s]\\d+[.\\d]*.*") || value.matches(".*\\d\\.\\d.*");
    }
}