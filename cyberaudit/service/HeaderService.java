package com.joao.cyberaudit.service;

import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

@Service
public class HeaderService {

    public Map<String, String> analyzeSecurityHeaders(Map<String, String> headersLowerCase) {
        Map<String, String> result = new HashMap<>();

        analyzeXFrame(headersLowerCase, result);
        analyzeContentType(headersLowerCase, result);
        analyzeHsts(headersLowerCase, result);
        analyzeCsp(headersLowerCase, result);

        return result;
    }

    private void analyzeXFrame(Map<String, String> h, Map<String, String> out) {
        String v = h.get("x-frame-options");
        if (v == null) out.put("X-Frame-Options", "MISSING");
        else if (v.equalsIgnoreCase("DENY")) out.put("X-Frame-Options", "OK (DENY)");
        else if (v.equalsIgnoreCase("SAMEORIGIN")) out.put("X-Frame-Options", "WEAK (SAMEORIGIN)");
        else out.put("X-Frame-Options", "UNKNOWN VALUE (" + v + ")");
    }

    private void analyzeContentType(Map<String, String> h, Map<String, String> out) {
        String v = h.get("x-content-type-options");
        if (v == null) out.put("X-Content-Type-Options", "MISSING");
        else if (v.equalsIgnoreCase("nosniff")) out.put("X-Content-Type-Options", "OK (nosniff)");
        else out.put("X-Content-Type-Options", "WEAK (" + v + ")");
    }

    private void analyzeHsts(Map<String, String> h, Map<String, String> out) {
        String v = h.get("strict-transport-security");
        if (v == null) out.put("Strict-Transport-Security", "MISSING");
        else if (v.toLowerCase(Locale.ROOT).contains("max-age=")) out.put("Strict-Transport-Security", "OK (" + v + ")");
        else out.put("Strict-Transport-Security", "WEAK (" + v + ")");
    }

    private void analyzeCsp(Map<String, String> h, Map<String, String> out) {
        String v = h.get("content-security-policy");
        if (v == null) out.put("Content-Security-Policy", "MISSING");
        else if (v.contains("default-src")) out.put("Content-Security-Policy", "OK");
        else out.put("Content-Security-Policy", "WEAK (" + v + ")");
    }
}