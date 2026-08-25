package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.*;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
public class ScoreService {

    private final MessageCatalog catalog;

    public ScoreService(MessageCatalog catalog) {
        this.catalog = catalog;
    }

    /**
     * Achado cujo ID é a própria chave do catálogo e cujo texto sai inteiro dele.
     * {@code argsTitulo} preenche os parâmetros do título, quando houver.
     *
     * Os achados que NÃO passam por aqui são os três casos que o catálogo não
     * cobre sozinho: impacto vindo de outro serviço (DNS, HTTP methods, JWT, API
     * docs, CVE), ID montado em tempo de execução, ou parâmetro no impacto em vez
     * do título. Esses montam o SecurityIssue à mão, chamando o catálogo campo a
     * campo.
     */
    private SecurityIssue achado(String chave, String severidade, Object... argsTitulo) {
        return new SecurityIssue(chave, catalog.title(chave, argsTitulo), severidade,
                catalog.impact(chave), catalog.recommendation(chave));
    }

    public ScoreResult calculate(
            SSLInfo sslInfo,
            TlsDetails tlsDetails,
            Map<String, String> headers,
            boolean redirectsToHttps,
            boolean activeMode,
            boolean inputSurfaceDetected,
            boolean dbErrorLeakageSuspected,
            boolean xssProbePerformed,
            boolean reflectedXssSuspected,
            List<PortFinding> openPorts,
            CorsResult corsResult,
            List<CookieFinding> cookieIssues,
            List<String> sensitiveRobotsPaths,
            boolean serverVersionExposed,
            List<SensitiveFileFinding> sensitiveFiles,
            List<HttpMethodFinding> dangerousHttpMethods,
            boolean securityTxtPresent,
            List<OpenRedirectFinding> openRedirectFindings,
            List<DirectoryListingFinding> directoryListingFindings,
            DnsSecurityResult dnsSecurityResult,
            WafDetectionResult wafDetectionResult,
            List<CVEFinding> cveFindings,
            List<ApiDocsExposureFinding> apiDocsExposure,
            List<GraphQlIntrospectionFinding> graphQlIntrospection,
            List<JwtSecurityFinding> jwtSecurity,
            List<PathTraversalFinding> pathTraversal,
            List<SsrfFinding> ssrfFindings,
            List<HostHeaderFinding> hostHeaderFindings,
            List<SourceMapFinding> sourceMapFindings,
            List<CrlfFinding> crlfFindings
    ) {
        int score = 100;
        List<String> notes  = new ArrayList<>();
        List<SecurityIssue> issues = new ArrayList<>();

        // ═══════════════════════════════════════════
        // 1. SSL / HTTPS
        // ═══════════════════════════════════════════
        if (!sslInfo.isHttps()) {
            score -= 40;
            notes.add(catalog.note("NO_HTTPS_SUPPORT"));
            issues.add(achado("NO_HTTPS_SUPPORT", "HIGH"));

        } else if (!sslInfo.isValid()) {
            score -= 35;
            notes.add(catalog.note("SSL_INVALID"));
            issues.add(achado("SSL_INVALID", "HIGH"));

        } else {
            notes.add(catalog.note("SSL_OK"));
            long days = sslInfo.getDaysRemaining();

            if (days <= 0) {
                score -= 35;
                notes.add(catalog.note("SSL_EXPIRED"));
                issues.add(achado("SSL_EXPIRED", "HIGH"));

            } else if (days < renewalWarningThreshold(sslInfo.getTotalValidityDays())) {
                score -= 15;
                notes.add(catalog.note("SSL_EXPIRING_SOON"));
                // Único caso em que o parâmetro está no impacto, não no título.
                issues.add(new SecurityIssue("SSL_EXPIRING_SOON",
                        catalog.title("SSL_EXPIRING_SOON"), "MEDIUM",
                        catalog.impact("SSL_EXPIRING_SOON", days),
                        catalog.recommendation("SSL_EXPIRING_SOON")));
            }
        }

        // ═══════════════════════════════════════════
        // 2. Protocolo TLS
        // ═══════════════════════════════════════════
        if (tlsDetails != null && tlsDetails.isWeakProtocol()) {
            score -= 20;
            notes.add(catalog.note("WEAK_TLS_PROTOCOL", tlsDetails.getNegotiatedProtocol()));
            issues.add(achado("WEAK_TLS_PROTOCOL", "HIGH", tlsDetails.getNegotiatedProtocol()));
        }

        // ═══════════════════════════════════════════
        // 3. Redirect HTTP → HTTPS
        // ═══════════════════════════════════════════
        if (sslInfo.isHttps() && sslInfo.isValid() && !redirectsToHttps) {
            score -= 10;
            notes.add(catalog.note("HTTP_NOT_REDIRECTING"));
            issues.add(achado("HTTP_NOT_REDIRECTING", "MEDIUM"));
        }

        // ═══════════════════════════════════════════
        // 4. Security Headers
        // ═══════════════════════════════════════════
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            String header = entry.getKey();
            String status = entry.getValue();
            if (status == null) continue;

            if (header.equalsIgnoreCase("error")) {
                // Fetch falhou: nenhum header de segurança pôde ser verificado. Penalidade
                // representativa de "headers não verificados" + issue (resultado parcial).
                score -= 35;
                notes.add(catalog.note("HEADERS_UNVERIFIED"));
                issues.add(achado("HEADERS_UNVERIFIED", "MEDIUM"));
                continue;
            }

            score = scoreHeader(header, status, score, notes, issues);
        }

        if (serverVersionExposed) {
            score -= 5;
            notes.add(catalog.note("SERVER_VERSION_EXPOSED"));
            issues.add(achado("SERVER_VERSION_EXPOSED", "LOW"));
        }

        // ═══════════════════════════════════════════
        // 5. CORS
        // ═══════════════════════════════════════════
        if (corsResult != null && corsResult.isTested()) {

            if (corsResult.isReflectsOrigin() && corsResult.isCredentialsAllowed()) {
                score -= 30;
                notes.add(catalog.note("CORS_REFLECTION_WITH_CREDENTIALS"));
                issues.add(achado("CORS_REFLECTION_WITH_CREDENTIALS", "CRITICAL"));

            } else if (corsResult.isReflectsOrigin()) {
                score -= 20;
                notes.add(catalog.note("CORS_ORIGIN_REFLECTION"));
                issues.add(achado("CORS_ORIGIN_REFLECTION", "HIGH"));

            } else if (corsResult.isWildcardOrigin() && corsResult.isCredentialsAllowed()) {
                score -= 15;
                notes.add(catalog.note("CORS_WILDCARD_CREDENTIALS"));
                issues.add(achado("CORS_WILDCARD_CREDENTIALS", "HIGH"));

            } else if (corsResult.isNullOriginAccepted()) {
                score -= 10;
                notes.add(catalog.note("CORS_NULL_ORIGIN"));
                issues.add(achado("CORS_NULL_ORIGIN", "MEDIUM"));
            }
        }

        // ═══════════════════════════════════════════
        // 6. Cookies
        // ═══════════════════════════════════════════
        if (cookieIssues != null && !cookieIssues.isEmpty()) {
            int penalty = 0;
            for (CookieFinding c : cookieIssues) {
                if ("HIGH".equals(c.getRisk()))   penalty = Math.max(penalty, 10);
                if ("MEDIUM".equals(c.getRisk())) penalty = Math.max(penalty, 5);
            }
            if (penalty > 0) {
                score -= penalty;
                notes.add(catalog.note("INSECURE_COOKIES", penalty));
                issues.add(achado("INSECURE_COOKIES", "MEDIUM", cookieIssues.size()));
            }
        }

        // ═══════════════════════════════════════════
        // 7. Checks ativos
        // ═══════════════════════════════════════════
        if (inputSurfaceDetected) {
            notes.add(catalog.note("INPUT_SURFACE"));
        }

        if (activeMode && dbErrorLeakageSuspected) {
            score -= 15;
            notes.add(catalog.note("DB_ERROR_LEAKAGE_SUSPECTED"));
            issues.add(achado("DB_ERROR_LEAKAGE_SUSPECTED", "HIGH"));
        }

        if (activeMode && xssProbePerformed && reflectedXssSuspected) {
            score -= 25;
            notes.add(catalog.note("REFLECTED_XSS_SUSPECTED"));
            issues.add(achado("REFLECTED_XSS_SUSPECTED", "HIGH"));
        }

        // ═══════════════════════════════════════════
        // 8. Port scan (ativo)
        // ═══════════════════════════════════════════
        if (openPorts != null && !openPorts.isEmpty() && activeMode) {
            int portPenalty = 0;
            int riskyCount  = 0;
            for (PortFinding p : openPorts) {
                // 80/443 abertos são esperados (servir HTTP/HTTPS) — não penalizar.
                if (p.getPort() == 80 || p.getPort() == 443) continue;
                int penalty = switch (p.getSeverity()) {
                    case "CRITICAL" -> 15;
                    case "HIGH" -> 10;
                    case "MEDIUM" -> 5;
                    default -> 2;
                };
                portPenalty += penalty;
                riskyCount++;
            }
            if (portPenalty > 0) {
                portPenalty = Math.min(portPenalty, 30);
                score -= portPenalty;
                notes.add(catalog.note("RISKY_PORTS", riskyCount, portPenalty));
                score = Math.max(0, score);
            }
        }

        // ═══════════════════════════════════════════
        // 9. robots.txt
        // ═══════════════════════════════════════════
        if (sensitiveRobotsPaths != null && !sensitiveRobotsPaths.isEmpty()) {
            score -= 5;
            notes.add(catalog.note("SENSITIVE_ROBOTS_PATHS"));
            issues.add(achado("SENSITIVE_ROBOTS_PATHS", "LOW", sensitiveRobotsPaths.size()));
        }

        // ═══════════════════════════════════════════════════════
        // 10. Arquivos sensíveis expostos
        // ═══════════════════════════════════════════════════════
        if (sensitiveFiles != null) {
            for (SensitiveFileFinding f : sensitiveFiles) {
                if ("EXPOSED".equals(f.getExposure())) {
                    int penalty = switch (f.getSeverity()) {
                        case "CRITICAL" -> 30;
                        case "HIGH"     -> 20;
                        default         -> 10;
                    };
                    score -= penalty;
                    notes.add(catalog.note("SENSITIVE_FILE_EXPOSED", f.getPath(), penalty));
                    issues.add(achado("SENSITIVE_FILE_EXPOSED", f.getSeverity(), f.getPath()));
                }
            }
        }

        // ═══════════════════════════════════════════════════════
        // 11. HTTP Methods perigosos
        // ═══════════════════════════════════════════════════════
        if (dangerousHttpMethods != null) {
            for (HttpMethodFinding m : dangerousHttpMethods) {
                int penalty = switch (m.getSeverity()) {
                    case "CRITICAL" -> 20;
                    case "HIGH"     -> 15;
                    case "MEDIUM"   -> 8;
                    default         -> 3;
                };
                score -= penalty;
                notes.add(catalog.note("DANGEROUS_HTTP_METHOD", m.getMethod(), penalty));
                // O impacto é o risco que o HttpMethodService descreveu — não sai do catálogo.
                issues.add(new SecurityIssue(
                        "DANGEROUS_HTTP_METHOD",
                        catalog.title("DANGEROUS_HTTP_METHOD", m.getMethod()),
                        m.getSeverity(),
                        m.getRisk(),
                        catalog.recommendation("DANGEROUS_HTTP_METHOD")
                ));
            }
        }

        // ═══════════════════════════════════════════════════════
        // 12. security.txt
        // ═══════════════════════════════════════════════════════
        if (!securityTxtPresent) {
            score -= 3;
            notes.add(catalog.note("SECURITY_TXT_MISSING"));
            issues.add(achado("SECURITY_TXT_MISSING", "LOW"));
        }

        // ═══════════════════════════════════════════════════════
        // 13. Open Redirect
        // ═══════════════════════════════════════════════════════
        if (openRedirectFindings != null) {
            long vulnerable = openRedirectFindings.stream()
                    .filter(OpenRedirectFinding::isVulnerable)
                    .count();
            if (vulnerable > 0) {
                score -= 20;
                notes.add(catalog.note("OPEN_REDIRECT", vulnerable));
                issues.add(achado("OPEN_REDIRECT", "HIGH"));
            }
        }

        // ═══════════════════════════════════════════════════════
        // 14. Directory Listing
        // ═══════════════════════════════════════════════════════
        if (directoryListingFindings != null) {
            for (DirectoryListingFinding d : directoryListingFindings) {
                if (d.isListingEnabled()) {
                    int penalty = switch (d.getSeverity()) {
                        case "CRITICAL" -> 25;
                        case "HIGH"     -> 15;
                        default         -> 8;
                    };
                    score -= penalty;
                    notes.add(catalog.note("DIRECTORY_LISTING", d.getPath(), penalty));
                    issues.add(achado("DIRECTORY_LISTING", d.getSeverity(), d.getPath()));
                }
            }
        }

        // ═══════════════════════════════════════════════════════
        // 15. DNS Security
        // ═══════════════════════════════════════════════════════
        if (dnsSecurityResult != null) {
            int penalty = switch (dnsSecurityResult.getEmailSpoofingRisk()) {
                case "CRITICAL" -> 20;
                case "HIGH"     -> 12;
                case "MEDIUM"   ->  6;
                default         ->  0;
            };
            if (penalty > 0) {
                score -= penalty;
                notes.add(catalog.note("DNS_EMAIL_SPOOFING",
                        dnsSecurityResult.getEmailSpoofingRisk(), penalty));
                // Severidade da issue = nível de risco DNS (CRITICAL/HIGH/MEDIUM)
                // Evita inconsistência entre o que o risco indica e o que a issue exibe
                // O impacto é o resumo que o DnsSecurityService montou — não sai do catálogo.
                issues.add(new SecurityIssue(
                        "DNS_EMAIL_SPOOFING",
                        catalog.title("DNS_EMAIL_SPOOFING", dnsSecurityResult.getEmailSpoofingRisk()),
                        dnsSecurityResult.getEmailSpoofingRisk(),
                        dnsSecurityResult.getSummary(),
                        catalog.recommendation("DNS_EMAIL_SPOOFING")
                ));
            }
        }

        // ═══════════════════════════════════════════════════════
        // 16. WAF Detection
        // ═══════════════════════════════════════════════════════
        if (wafDetectionResult != null) {
            if (!wafDetectionResult.isDetected()) {
                score -= 3;
                notes.add(catalog.note("NO_WAF_DETECTED"));
                issues.add(achado("NO_WAF_DETECTED", "LOW"));
            } else {
                // WAF detectado — bônus apenas para WAFs reais.
                // CDNs (Vercel, GitHub, Fastly, Google Cloud) não conferem proteção
                // contra ataques e não recebem bônus de score.
                String  category     = wafDetectionResult.getCategory();
                boolean isRealWaf    = "WAF".equals(category) || "BOTH".equals(category);
                boolean probeBlocked = "BLOCKED".equals(wafDetectionResult.getProbeResponse());
                String  confidence   = wafDetectionResult.getConfidence();

                if (isRealWaf) {
                    int bonus = 0;
                    if (probeBlocked && "HIGH".equals(confidence))   bonus = 8;
                    else if (probeBlocked)                           bonus = 5;
                    else if ("HIGH".equals(confidence))              bonus = 4;
                    else if ("MEDIUM".equals(confidence))            bonus = 2;
                    else                                             bonus = 1;

                    score += bonus;
                    notes.add(catalog.note("WAF_DETECTED", wafDetectionResult.getProvider(),
                            probeBlocked ? catalog.note("WAF_PROBE_BLOCKED") : "", bonus));
                } else {
                    // CDN detectado — informativo, sem bônus de score
                    notes.add(catalog.note("CDN_DETECTED", wafDetectionResult.getProvider()));
                }
            }
        }


        // ═══════════════════════════════════════════════════════
        // 17. CVE Correlation — apenas CVSS >= 7.0 (HIGH/CRITICAL)
        // Achados POTENCIAIS (correlação por versão de banner): penalidade reduzida
        // (CRITICAL -10, HIGH -6; máx -16), severidade da issue rebaixada um tier e
        // rótulo "[Potencial]" + disclaimer na recomendação.
        // ═══════════════════════════════════════════════════════
        if (cveFindings != null && !cveFindings.isEmpty()) {
            int cvePenaltyTotal = 0;
            java.util.Set<String> seenIds      = new java.util.HashSet<>();
            java.util.Set<String> chargedTiers = new java.util.HashSet<>(); // tiers já descontados

            for (CVEFinding cve : cveFindings) {
                if (!seenIds.add(cve.getCveId())) continue;  // dedup por CVE ID
                if (cve.getCvssScore() < 7.0) continue;       // ignorar LOW/MEDIUM

                String tier = cve.getCvssScore() >= 9.0 ? "CRITICAL" : "HIGH";

                // Desconta pontos apenas na primeira ocorrência de cada tier
                if (chargedTiers.add(tier)) {
                    int penalty = tier.equals("CRITICAL") ? 10 : 6;
                    cvePenaltyTotal += penalty;
                    notes.add(catalog.note("CVE", tier, penalty));
                }

                // Chave base "CVE": o ID do achado carrega o número, que muda a cada
                // achado. A descrição vem do NVD, em inglês na origem — não passa
                // pelo catálogo porque não há o que traduzir do nosso lado.
                String recommendation = catalog.recommendation("CVE", cve.getAffectedSoftware())
                        + (cve.getReferenceUrl() != null
                           ? catalog.fragment("CVE", "reference", cve.getReferenceUrl()) : "");

                issues.add(new SecurityIssue(
                        "CVE_" + cve.getCveId().replace("-", "_"),
                        catalog.title("CVE", cve.getCveId(), cve.getAffectedSoftware(),
                                String.format("%.1f", cve.getCvssScore())),
                        downgradeOneTier(cve.getSeverity()),
                        cve.getDescription(),
                        recommendation
                ));
            }

            score -= cvePenaltyTotal;  // máx -16 pts (CRITICAL + HIGH, potencial)
        }

        // Path Traversal penalty — CRITICAL: -15 pts por finding, cap -20
        if (pathTraversal != null && !pathTraversal.isEmpty()) {
            int ptPenalty = Math.min(pathTraversal.size() * 15, 20);
            score -= ptPenalty;
            notes.add(catalog.note("PATH_TRAVERSAL", pathTraversal.size(), ptPenalty));
        }

        // SSRF penalty — CRITICAL: -15 pts per finding, cap -20
        if (ssrfFindings != null && !ssrfFindings.isEmpty()) {
            int ssrfPenalty = Math.min(ssrfFindings.size() * 15, 20);
            score -= ssrfPenalty;
            notes.add(catalog.note("SSRF", ssrfFindings.size(), ssrfPenalty));
        }

        // Host Header Injection penalty — só vetores exploráveis (HIGH/CRITICAL =
        // Location/Set-Cookie). Reflexão só-no-body é LOW (informativa) e não penaliza.
        if (hostHeaderFindings != null && !hostHeaderFindings.isEmpty()) {
            long exploitable = hostHeaderFindings.stream()
                    .filter(h -> "HIGH".equals(h.getSeverity()) || "CRITICAL".equals(h.getSeverity()))
                    .count();
            if (exploitable > 0) {
                int hhPenalty = (int) Math.min(exploitable * 10, 15);
                score -= hhPenalty;
                notes.add(catalog.note("HOST_HEADER", exploitable, hhPenalty));
            }
        }

        // Source Map / Debug Exposure penalty
        // HIGH findings (source map, actuator/env): -8 pts each, cap -15
        // MEDIUM findings (debug endpoints): -4 pts each, cap -8
        if (sourceMapFindings != null && !sourceMapFindings.isEmpty()) {
            long highCount   = sourceMapFindings.stream().filter(f -> "HIGH".equals(f.getSeverity())).count();
            long mediumCount = sourceMapFindings.stream().filter(f -> "MEDIUM".equals(f.getSeverity())).count();
            int smPenalty = (int) Math.min(highCount * 8, 15) + (int) Math.min(mediumCount * 4, 8);
            score -= smPenalty;
            notes.add(catalog.note("SOURCE_MAP", sourceMapFindings.size(), smPenalty));
        }

        // CRLF Injection penalty — HIGH: -12 pts per finding, cap -18
        if (crlfFindings != null && !crlfFindings.isEmpty()) {
            int crlfPenalty = Math.min(crlfFindings.size() * 12, 18);
            score -= crlfPenalty;
            notes.add(catalog.note("CRLF", crlfFindings.size(), crlfPenalty));
        }

        // JWT Security penalty
        // alg:none         — CRITICAL: -15 pts
        // sem expiracao    — HIGH: -8 pts
        // algoritmo fraco  — MEDIUM: -4 pts
        // sem iss/aud      — LOW: -2 pts
        // Cap: -15 pts total
        if (jwtSecurity != null && !jwtSecurity.isEmpty()) {
            int jwtPenalty = 0;
            for (JwtSecurityFinding jwt : jwtSecurity) {
                int p = switch (jwt.getSeverity()) {
                    case "CRITICAL" -> 15;
                    case "HIGH"     -> 8;
                    case "MEDIUM"   -> 4;
                    default          -> 2;
                };
                jwtPenalty = Math.max(jwtPenalty, p); // pega o pior caso
                String issueDesc = String.join("; ", jwt.getIssues());
                // Chave base "JWT": o ID carrega a severidade. O impacto é a lista de
                // problemas que o JwtSecurityService encontrou.
                issues.add(new SecurityIssue(
                        "JWT_" + jwt.getSeverity(),
                        catalog.title("JWT", jwt.getSource(), jwt.getAlgorithm()),
                        jwt.getSeverity(),
                        issueDesc,
                        catalog.recommendation("JWT")
                ));
            }
            score -= jwtPenalty;
            notes.add(catalog.note("JWT", jwtPenalty));
        }

        // GraphQL Introspection penalty
        // Introspection habilitada em producao: -5 pts (schema completo exposto)
        // Playground exposto: -8 pts (UI interativa sem auth)
        // Cap: -8 pts total por endpoint
        if (graphQlIntrospection != null && !graphQlIntrospection.isEmpty()) {
            for (GraphQlIntrospectionFinding gql : graphQlIntrospection) {
                int gqlPenalty = gql.isPlaygroundExposed() ? 8 : 5;
                score -= gqlPenalty;
                notes.add(catalog.note(
                        gql.isPlaygroundExposed() ? "GRAPHQL_PLAYGROUND" : "GRAPHQL_INTROSPECTION",
                        gql.getEndpoint(), gqlPenalty));
                String tc = gql.getTypeCount() > 0
                        ? catalog.fragment("GRAPHQL", "typeCount", gql.getTypeCount()) : "";
                // Playground e introspection têm títulos e impactos diferentes, mas a
                // mesma recomendação — daí a chave base separada só para ela.
                String chave = "GRAPHQL_" + (gql.isPlaygroundExposed() ? "PLAYGROUND" : "INTROSPECTION");
                issues.add(new SecurityIssue(
                        chave,
                        catalog.title(chave, gql.getEndpoint(), tc),
                        gql.getSeverity(),
                        catalog.impact(chave),
                        catalog.recommendation("GRAPHQL")
                ));
            }
        }

        // API docs exposure penalty
        // Cada endpoint exposto e -3 pts, cap de -8 pts total.
        // Severidade HIGH (spec JSON/YAML) gera issue MEDIUM no score;
        // MEDIUM (UI) gera issue LOW — informacional mas relevante.
        if (apiDocsExposure != null && !apiDocsExposure.isEmpty()) {
            int apiPenalty = Math.min(apiDocsExposure.size() * 3, 8);
            score -= apiPenalty;
            notes.add(catalog.note("API_DOCS", apiDocsExposure.size(), apiPenalty));
            for (ApiDocsExposureFinding f : apiDocsExposure) {
                String issueSev = "HIGH".equals(f.getSeverity()) ? "MEDIUM" : "LOW";
                // Chave base "API_DOCS": o ID carrega o tipo. O impacto vem do
                // ApiDocsExposureService.
                issues.add(new SecurityIssue(
                        "API_DOCS_" + f.getType(),
                        catalog.title("API_DOCS", f.getPath()),
                        issueSev,
                        f.getDescription(),
                        catalog.recommendation("API_DOCS")
                ));
            }
        }

        score = Math.max(0, score);

        // ── Risk level — 5 tiers ─────────────────────────────────────────────
        RiskLevel risk;
        if      (score >= 85) risk = RiskLevel.SECURE;
        else if (score >= 70) risk = RiskLevel.LOW;
        else if (score >= 45) risk = RiskLevel.MEDIUM;
        else if (score >= 20) risk = RiskLevel.HIGH;
        else                  risk = RiskLevel.CRITICAL;

        // ── Severity override ─────────────────────────────────────────────────
        // Garante que findings exploráveis forcem um nível mínimo de risco,
        // independente de outros fatores positivos (WAF bonus, etc.)
        boolean hasCriticalIssue = issues.stream()
                .anyMatch(i -> "CRITICAL".equals(i.getSeverity()));
        boolean hasHighIssue = issues.stream()
                .anyMatch(i -> "HIGH".equals(i.getSeverity()));

        if (hasCriticalIssue && risk.ordinal() < RiskLevel.HIGH.ordinal()) {
            risk = RiskLevel.HIGH;
        }
        if (hasHighIssue && risk.ordinal() < RiskLevel.MEDIUM.ordinal()) {
            risk = RiskLevel.MEDIUM;
        }

        return new ScoreResult(score, risk, notes, issues);
    }

    /** Rebaixa a severidade em um tier (CRITICAL→HIGH→MEDIUM→LOW). */
    private String downgradeOneTier(String severity) {
        return switch (severity == null ? "" : severity.toUpperCase()) {
            case "CRITICAL" -> "HIGH";
            case "HIGH"     -> "MEDIUM";
            case "MEDIUM"   -> "LOW";
            default          -> "LOW";
        };
    }

    // ── Header scoring ────────────────────────────────────

    private int scoreHeader(String header, String status, int score,
                            List<String> notes, List<SecurityIssue> issues) {
        return switch (header) {

            case "Strict-Transport-Security" -> {
                if (status.startsWith("MISSING")) {
                    notes.add(catalog.note("HSTS_MISSING"));
                    issues.add(achado("HSTS_MISSING", "HIGH"));
                    yield score - 10;
                } else if (status.startsWith("WEAK")) {
                    notes.add(catalog.note("HSTS_WEAK"));
                    issues.add(achado("HSTS_WEAK", "MEDIUM"));
                    yield score - 5;
                }
                yield score;
            }

            case "X-Content-Type-Options" -> {
                if (status.startsWith("MISSING")) {
                    notes.add(catalog.note("CONTENT_TYPE_MISSING"));
                    issues.add(achado("CONTENT_TYPE_MISSING", "MEDIUM"));
                    yield score - 5;
                }
                yield score;
            }

            case "Content-Security-Policy" -> {
                if (status.startsWith("MISSING")) {
                    notes.add(catalog.note("CSP_MISSING"));
                    issues.add(achado("CSP_MISSING", "HIGH"));
                    yield score - 10;
                } else if (status.startsWith("WEAK")) {
                    notes.add(catalog.note("CSP_WEAK"));
                    issues.add(achado("CSP_WEAK", "MEDIUM"));
                    yield score - 5;
                }
                yield score;
            }

            case "X-Frame-Options" -> {
                if (status.startsWith("MISSING")) {
                    notes.add(catalog.note("XFRAME_MISSING"));
                    issues.add(achado("XFRAME_MISSING", "MEDIUM"));
                    yield score - 5;
                }
                yield score;
            }

            case "Referrer-Policy" -> {
                if (status.startsWith("MISSING")) {
                    notes.add(catalog.note("REFERRER_POLICY_MISSING"));
                    issues.add(achado("REFERRER_POLICY_MISSING", "LOW"));
                    yield score - 5;
                } else if (status.startsWith("WEAK")) {
                    notes.add(catalog.note("REFERRER_POLICY_WEAK"));
                    issues.add(achado("REFERRER_POLICY_WEAK", "MEDIUM"));
                    yield score - 5;
                }
                yield score;
            }

            case "Permissions-Policy" -> {
                if (status.startsWith("MISSING")) {
                    notes.add(catalog.note("PERMISSIONS_POLICY_MISSING"));
                    issues.add(achado("PERMISSIONS_POLICY_MISSING", "LOW"));
                    yield score - 3;
                }
                yield score;
            }

            default -> score;
        };
    }

    // ── Expiração de certificado ──────────────────────────────────────────────

    /** Fração da vida útil abaixo da qual a renovação é considerada em falha. */
    private static final double RENEWAL_WARNING_FRACTION = 0.10;

    /**
     * Teto absoluto do aviso. Impede que certificado de vida muito longa
     * (CA interna com validade de anos) dispare alerta com meses de folga.
     */
    private static final long RENEWAL_WARNING_MAX_DAYS = 30;

    /** Piso absoluto, para o caso de a vida útil total ser desconhecida. */
    private static final long RENEWAL_WARNING_FALLBACK_DAYS = 7;

    /**
     * A partir de quantos dias restantes vale alertar sobre a expiração.
     *
     * Em PROPORÇÃO à vida útil, não em dias absolutos. A regra anterior descontava
     * pontos de qualquer certificado com 90 dias ou menos — o que era impossível de
     * satisfazer, já que 90 dias é a vida ÚTIL INTEIRA de um Let's Encrypt: todo
     * usuário nascia penalizado e levava -20 durante a renovação normal, aos 30 dias.
     *
     * O CA/Browser Forum está reduzindo o máximo de 398 para 200 dias (2026), 100
     * (2027) e 47 (2029), então ciclos curtos são a norma que vem por aí — julgar por
     * dias absolutos ficaria cada vez mais errado.
     *
     * Exemplos: Let's Encrypt de 90 dias alerta abaixo de 9; certificado de 47 dias,
     * abaixo de ~5; anual de 398 dias, abaixo de 30 (o teto).
     */
    private long renewalWarningThreshold(long totalValidityDays) {
        if (totalValidityDays <= 0) return RENEWAL_WARNING_FALLBACK_DAYS;
        long proportional = Math.round(totalValidityDays * RENEWAL_WARNING_FRACTION);
        return Math.min(Math.max(proportional, 1), RENEWAL_WARNING_MAX_DAYS);
    }
}