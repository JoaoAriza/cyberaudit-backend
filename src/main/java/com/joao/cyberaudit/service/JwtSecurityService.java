package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.JwtSecurityFinding;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class JwtSecurityService {

    /**
     * Regex para detectar JWTs: 3 segmentos Base64URL separados por ponto.
     * Base64URL usa [A-Za-z0-9_-] (sem +, /, =).
     * Cada segmento tem no minimo 4 chars para evitar FPs com versoes semânticas (1.2.3).
     */
    private static final Pattern JWT_PATTERN = Pattern.compile(
            "([A-Za-z0-9_-]{4,})\\." +
            "([A-Za-z0-9_-]{4,})\\." +
            "([A-Za-z0-9_-]{0,})"   // assinatura pode ser vazia (alg:none)
    );

    /** Algoritmos simetricos — seguranca depende inteiramente da forca do segredo */
    private static final List<String> SYMMETRIC_ALGS = List.of(
            "HS256", "HS384", "HS512"
    );

    /**
     * Analisa cookies e headers em busca de JWTs e inspeciona seus claims.
     *
     * Operacao passiva: nao faz requests adicionais, apenas decodifica tokens
     * ja recebidos na resposta HTTP do scan principal.
     *
     * @param rawSetCookies  lista de Set-Cookie headers brutos
     * @param responseHeaders mapa de headers da resposta (para checar Authorization)
     */
    public List<JwtSecurityFinding> analyze(List<String> rawSetCookies,
                                             Map<String, String> responseHeaders) {
        List<JwtSecurityFinding> findings = new ArrayList<>();

        // Checar cookies
        if (rawSetCookies != null) {
            for (String cookieHeader : rawSetCookies) {
                String cookieName  = extractCookieName(cookieHeader);
                String cookieValue = extractCookieValue(cookieHeader);
                if (cookieValue == null) continue;

                JwtSecurityFinding finding = analyzeToken(cookieName, cookieValue);
                if (finding != null) findings.add(finding);
            }
        }

        // Checar Authorization header (Bearer token)
        if (responseHeaders != null) {
            String authHeader = responseHeaders.getOrDefault("authorization",
                    responseHeaders.getOrDefault("Authorization", null));
            if (authHeader != null && authHeader.toLowerCase(Locale.ROOT).startsWith("bearer ")) {
                String token = authHeader.substring(7).trim();
                JwtSecurityFinding finding = analyzeToken("Authorization", token);
                if (finding != null) findings.add(finding);
            }
        }

        return findings;
    }

    /**
     * Tenta decodificar e analisar um token JWT.
     * Retorna null se o valor nao for um JWT valido.
     */
    private JwtSecurityFinding analyzeToken(String source, String value) {
        // Extrai o JWT do valor (pode estar prefixado com "Bearer " ou ter padding)
        String token = extractJwt(value);
        if (token == null) return null;

        String[] parts = token.split("\\.");
        if (parts.length < 2) return null;

        // Decodifica header
        String headerJson = decodeBase64Url(parts[0]);
        if (headerJson == null) return null;

        // Decodifica payload
        String payloadJson = parts.length >= 2 ? decodeBase64Url(parts[1]) : null;

        // Extrai algoritmo do header
        String alg = extractJsonString(headerJson, "alg");
        if (alg == null) alg = "UNKNOWN";

        // Analisa payload claims
        boolean hasExpiry   = false;
        boolean expired     = false;
        boolean hasIssuer   = false;
        boolean hasAudience = false;
        Long    expValue    = null;

        if (payloadJson != null) {
            hasExpiry   = payloadJson.contains("\"exp\"");
            hasIssuer   = payloadJson.contains("\"iss\"");
            hasAudience = payloadJson.contains("\"aud\"");

            if (hasExpiry) {
                expValue = extractJsonLong(payloadJson, "exp");
                if (expValue != null) {
                    expired = Instant.now().getEpochSecond() > expValue;
                }
            }
        }

        // Monta lista de issues
        List<String> issues = new ArrayList<>();

        String algUpper = alg.toUpperCase(Locale.ROOT);

        if ("NONE".equals(algUpper) || "\"NONE\"".equals(algUpper)) {
            issues.add("alg:none — token sem assinatura, pode ser forjado arbitrariamente");
        } else if (SYMMETRIC_ALGS.contains(algUpper)) {
            issues.add("Algoritmo simetrico (" + alg + ") — seguranca depende da forca do segredo compartilhado");
        }

        if (!hasExpiry) {
            issues.add("Sem claim 'exp' — token nao expira, valido indefinidamente");
        } else if (expired) {
            issues.add("Token expirado (exp=" + expValue + ") sendo servido pelo servidor");
        }

        if (!hasIssuer)   issues.add("Sem claim 'iss' — issuer nao validado");
        if (!hasAudience) issues.add("Sem claim 'aud' — audience nao validada");

        // Nao reportar se nao ha problemas reais
        if (issues.isEmpty()) return null;

        String severity = resolveSeverity(algUpper, hasExpiry, expired);

        // Evidencia: header decodificado (nao inclui payload — pode ter dados sensiveis)
        String evidence = "Header: " + truncate(headerJson, 120);
        if (!hasExpiry || expired) {
            // Adiciona info de expiracao ao evidence — sem dados sensiveis
            String expInfo = !hasExpiry ? "exp: ausente"
                    : "exp: " + expValue + " (expirado)";
            evidence += " | " + expInfo;
        }

        return JwtSecurityFinding.builder()
                .source(source)
                .algorithm(alg)
                .hasExpiry(hasExpiry)
                .expired(expired)
                .hasIssuer(hasIssuer)
                .hasAudience(hasAudience)
                .issues(issues)
                .severity(severity)
                .evidence(evidence)
                .build();
    }

    private String resolveSeverity(String algUpper, boolean hasExpiry, boolean expired) {
        if ("NONE".equals(algUpper)) return "CRITICAL";
        if (!hasExpiry || expired)   return "HIGH";
        if (SYMMETRIC_ALGS.contains(algUpper)) return "MEDIUM";
        return "LOW";
    }

    // ── Helpers de parsing ────────────────────────────────────────────────────

    /** Extrai o JWT de um valor que pode ter prefixo "Bearer " ou outros */
    private String extractJwt(String value) {
        if (value == null) return null;
        String v = value.trim();
        if (v.toLowerCase(Locale.ROOT).startsWith("bearer ")) v = v.substring(7).trim();

        Matcher m = JWT_PATTERN.matcher(v);
        if (!m.find()) return null;

        // Valida que o header decodifica para JSON com "alg" ou "typ"
        String candidate = m.group(0);
        String[] parts = candidate.split("\\.");
        if (parts.length < 2) return null;
        String header = decodeBase64Url(parts[0]);
        if (header == null) return null;
        // Header JWT real deve conter "alg" ou "typ"
        String lh = header.toLowerCase(Locale.ROOT);
        if (!lh.contains("\"alg\"") && !lh.contains("\"typ\"")) return null;

        return candidate;
    }

    private String extractCookieName(String cookieHeader) {
        if (cookieHeader == null) return "unknown";
        int eq = cookieHeader.indexOf('=');
        int sc = cookieHeader.indexOf(';');
        if (eq < 0) return cookieHeader.trim();
        return cookieHeader.substring(0, eq).trim();
    }

    private String extractCookieValue(String cookieHeader) {
        if (cookieHeader == null) return null;
        int eq = cookieHeader.indexOf('=');
        if (eq < 0 || eq >= cookieHeader.length() - 1) return null;
        int sc = cookieHeader.indexOf(';', eq);
        return sc > eq ? cookieHeader.substring(eq + 1, sc).trim()
                       : cookieHeader.substring(eq + 1).trim();
    }

    private String decodeBase64Url(String encoded) {
        try {
            // Base64URL pode nao ter padding — adicionar se necessario
            String padded = encoded;
            int rem = encoded.length() % 4;
            if (rem == 2) padded += "==";
            else if (rem == 3) padded += "=";
            byte[] decoded = Base64.getUrlDecoder().decode(padded);
            return new String(decoded, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    /** Extrai o valor de uma propriedade string de um JSON simples */
    private String extractJsonString(String json, String key) {
        Pattern p = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]+)\"");
        Matcher m = p.matcher(json);
        return m.find() ? m.group(1) : null;
    }

    /** Extrai o valor numerico de uma propriedade de um JSON simples */
    private Long extractJsonLong(String json, String key) {
        try {
            Pattern p = Pattern.compile("\"" + key + "\"\\s*:\\s*(\\d+)");
            Matcher m = p.matcher(json);
            return m.find() ? Long.parseLong(m.group(1)) : null;
        } catch (Exception e) {
            return null;
        }
    }

    private String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
