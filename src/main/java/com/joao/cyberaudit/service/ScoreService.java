package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.*;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
public class ScoreService {

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
            notes.add("HTTPS não suportado: -40");
            issues.add(new SecurityIssue("NO_HTTPS_SUPPORT", "HTTPS não suportado", "HIGH",
                    "Dados trafegam em plaintext — interceptação trivial.",
                    "Habilitar HTTPS com certificado válido (ex: Let's Encrypt)."));

        } else if (!sslInfo.isValid()) {
            score -= 35;
            notes.add("Certificado SSL inválido/erro: -35");
            issues.add(new SecurityIssue("SSL_INVALID", "Certificado SSL inválido", "HIGH",
                    "Usuários recebem alerta de segurança; comunicação pode ser insegura.",
                    "Renovar e configurar corretamente o certificado e a cadeia intermediária."));

        } else {
            notes.add("HTTPS e certificado válido: OK");
            long days = sslInfo.getDaysRemaining();

            if (days <= 0) {
                score -= 35;
                notes.add("Certificado expirado: -35");
                issues.add(new SecurityIssue("SSL_EXPIRED", "Certificado SSL expirado", "HIGH",
                        "Browsers bloqueiam ou alertam o usuário.",
                        "Renovar o certificado imediatamente."));

            } else if (days <= 30) {
                score -= 20;
                notes.add("Certificado expira em até 30 dias: -20");
                issues.add(new SecurityIssue("SSL_EXPIRING_SOON",
                        "Certificado próximo da expiração", "MEDIUM",
                        "Risco de indisponibilidade se não renovado.",
                        "Renovar antes da expiração."));

            } else if (days <= 90) {
                score -= 10;
                notes.add("Certificado expira em até 90 dias: -10");
            }
        }

        // ═══════════════════════════════════════════
        // 2. Protocolo TLS
        // ═══════════════════════════════════════════
        if (tlsDetails != null && tlsDetails.isWeakProtocol()) {
            score -= 20;
            notes.add("Protocolo TLS deprecated (" + tlsDetails.getNegotiatedProtocol() + "): -20");
            issues.add(new SecurityIssue("WEAK_TLS_PROTOCOL",
                    "Protocolo TLS deprecated: " + tlsDetails.getNegotiatedProtocol(), "HIGH",
                    "TLS 1.0/1.1 são deprecated pelo RFC 8996 — vulneráveis a POODLE e BEAST.",
                    "Desabilitar TLS 1.0 e 1.1 no servidor. Exigir mínimo TLS 1.2."));
        }

        // ═══════════════════════════════════════════
        // 3. Redirect HTTP → HTTPS
        // ═══════════════════════════════════════════
        if (sslInfo.isHttps() && sslInfo.isValid() && !redirectsToHttps) {
            score -= 10;
            notes.add("Não força HTTPS a partir de HTTP: -10");
            issues.add(new SecurityIssue("HTTP_NOT_REDIRECTING",
                    "HTTP não redireciona para HTTPS", "MEDIUM",
                    "Usuários que digitam http:// acessam sem criptografia.",
                    "Configurar redirect 301 de HTTP para HTTPS e habilitar HSTS."));
        }

        // ═══════════════════════════════════════════
        // 4. Security Headers
        // ═══════════════════════════════════════════
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            String header = entry.getKey();
            String status = entry.getValue();
            if (status == null) continue;

            if (header.equalsIgnoreCase("error")) {
                // Fetch falhou: NENHUM header de segurança pôde ser verificado. Antes isto
                // custava só -15 e pulava todas as penalidades de header (HSTS/CSP/etc, ~-38) —
                // então um timeout dava nota MELHOR que a análise real de um site inseguro.
                // Cobramos uma penalidade representativa de "headers não verificados" e
                // registramos como issue, sem fingir que as proteções estão presentes.
                score -= 35;
                notes.add("Headers de segurança não verificados (falha ao buscar a página): -35");
                issues.add(new SecurityIssue("HEADERS_UNVERIFIED",
                        "Headers de segurança não verificados", "MEDIUM",
                        "A página não respondeu, então nenhum header de segurança pôde ser avaliado. "
                        + "O resultado é parcial e não confirma a presença de proteções.",
                        "Verifique se o site está acessível (DNS, firewall, disponibilidade) e refaça o scan."));
                continue;
            }

            score = scoreHeader(header, status, score, notes, issues);
        }

        if (serverVersionExposed) {
            score -= 5;
            notes.add("Versão de software exposta (Server/X-Powered-By): -5");
            issues.add(new SecurityIssue("SERVER_VERSION_EXPOSED",
                    "Versão de software exposta em Server ou X-Powered-By", "LOW",
                    "Facilita fingerprinting e busca por CVEs conhecidos.",
                    "Remover ou obscurecer os headers Server e X-Powered-By."));
        }

        // ═══════════════════════════════════════════
        // 5. CORS
        // ═══════════════════════════════════════════
        if (corsResult != null && corsResult.isTested()) {

            if (corsResult.isReflectsOrigin() && corsResult.isCredentialsAllowed()) {
                score -= 30;
                notes.add("CORS reflection + credentials: -30");
                issues.add(new SecurityIssue("CORS_REFLECTION_WITH_CREDENTIALS",
                        "CORS reflete origin com credentials habilitado", "CRITICAL",
                        "Qualquer site faz requests autenticadas cross-origin em nome do usuário.",
                        "Allowlist estrita de origens. Nunca combinar reflection com ACAC: true."));

            } else if (corsResult.isReflectsOrigin()) {
                score -= 20;
                notes.add("CORS reflete a origem do request: -20");
                issues.add(new SecurityIssue("CORS_ORIGIN_REFLECTION",
                        "CORS reflete a Origin do request", "HIGH",
                        "Qualquer site acessa recursos como origem autorizada.",
                        "Usar allowlist estrita em vez de espelhar o header Origin."));

            } else if (corsResult.isWildcardOrigin() && corsResult.isCredentialsAllowed()) {
                score -= 15;
                notes.add("CORS wildcard + credentials (config inválida): -15");
                issues.add(new SecurityIssue("CORS_WILDCARD_CREDENTIALS",
                        "ACAO: * com ACAC: true — configuração inválida", "HIGH",
                        "Browsers rejeitam, mas indica CORS sem controle.",
                        "Usar origens explícitas. Nunca wildcard com credentials."));

            } else if (corsResult.isNullOriginAccepted()) {
                score -= 10;
                notes.add("CORS aceita null origin: -10");
                issues.add(new SecurityIssue("CORS_NULL_ORIGIN",
                        "Aceita null origin", "MEDIUM",
                        "Acesso via iframe sandboxado ou file:// — vetor de exfiltração.",
                        "Não incluir 'null' na allowlist de origens."));
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
                notes.add("Cookies com flags de segurança ausentes: -" + penalty);
                issues.add(new SecurityIssue("INSECURE_COOKIES",
                        cookieIssues.size() + " cookie(s) com problemas de segurança", "MEDIUM",
                        "Sem Secure/HttpOnly/SameSite: facilita roubo de sessão via XSS ou redes inseguras.",
                        "Adicionar Secure, HttpOnly e SameSite=Lax em todos os cookies de sessão."));
            }
        }

        // ═══════════════════════════════════════════
        // 7. Checks ativos
        // ═══════════════════════════════════════════
        if (inputSurfaceDetected) {
            notes.add("Superfície de entrada detectada (parâmetros na URL): INFO");
        }

        if (activeMode && dbErrorLeakageSuspected) {
            score -= 15;
            notes.add("Possível exposição de erro de banco (modo ativo): -15");
            issues.add(new SecurityIssue("DB_ERROR_LEAKAGE_SUSPECTED",
                    "Possível exposição de erro de banco", "HIGH",
                    "Mensagens de erro revelam estrutura do banco.",
                    "Retornar mensagens genéricas em produção. Logar erros só no servidor."));
        }

        if (activeMode && xssProbePerformed && reflectedXssSuspected) {
            score -= 25;
            notes.add("Suspeita de Reflected XSS (marcador refletido): -25");
            issues.add(new SecurityIssue("REFLECTED_XSS_SUSPECTED",
                    "Suspeita de Reflected XSS", "HIGH",
                    "Input parece refletido na página sem escape.",
                    "Output encoding, validação de inputs e CSP restritiva."));
        }

        // ═══════════════════════════════════════════
        // 8. Port scan (ativo)
        // ═══════════════════════════════════════════
        if (openPorts != null && !openPorts.isEmpty() && activeMode) {
            int portPenalty = 0;
            int riskyCount  = 0;
            for (PortFinding p : openPorts) {
                // 80/443 abertos são esperados (servir HTTP/HTTPS) — não penalizar.
                // "HTTP não redireciona p/ HTTPS" já é tratado na seção 3, sem double-dip.
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
                notes.add("Portas de risco abertas (" + riskyCount + "): -" + portPenalty);
                score = Math.max(0, score);
            }
        }

        // ═══════════════════════════════════════════
        // 9. robots.txt
        // ═══════════════════════════════════════════
        if (sensitiveRobotsPaths != null && !sensitiveRobotsPaths.isEmpty()) {
            score -= 5;
            notes.add("Paths sensíveis em robots.txt: -5");
            issues.add(new SecurityIssue("SENSITIVE_ROBOTS_PATHS",
                    sensitiveRobotsPaths.size() + " path(s) sensível(is) em robots.txt", "LOW",
                    "robots.txt funciona como mapa da estrutura interna para atacantes.",
                    "Não usar robots.txt para esconder paths. Use autenticação adequada."));
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
                    notes.add("Arquivo sensível exposto (" + f.getPath() + "): -" + penalty);
                    issues.add(new SecurityIssue(
                            "SENSITIVE_FILE_EXPOSED",
                            "Arquivo sensível acessível: " + f.getPath(),
                            f.getSeverity(),
                            "Exposição direta de configuração ou credenciais.",
                            "Remover acesso público imediatamente. Verificar se credenciais foram comprometidas."
                    ));
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
                notes.add("Método HTTP perigoso habilitado (" + m.getMethod() + "): -" + penalty);
                issues.add(new SecurityIssue(
                        "DANGEROUS_HTTP_METHOD",
                        "Método HTTP perigoso habilitado: " + m.getMethod(),
                        m.getSeverity(),
                        m.getRisk(),
                        "Desabilitar métodos HTTP não necessários no servidor web."
                ));
            }
        }

        // ═══════════════════════════════════════════════════════
        // 12. security.txt
        // ═══════════════════════════════════════════════════════
        if (!securityTxtPresent) {
            score -= 3;
            notes.add("security.txt ausente: -3");
            issues.add(new SecurityIssue(
                    "SECURITY_TXT_MISSING",
                    "security.txt ausente (RFC 9116)",
                    "LOW",
                    "Dificulta reporte responsável de vulnerabilidades.",
                    "Criar /.well-known/security.txt com campo Contact."
            ));
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
                notes.add("Open redirect detectado (" + vulnerable + " parâmetro(s)): -20");
                issues.add(new SecurityIssue(
                        "OPEN_REDIRECT",
                        "Open Redirect detectado",
                        "HIGH",
                        "Atacantes podem usar seu domínio como intermediário em ataques de phishing.",
                        "Validar e sanitizar todos os parâmetros de redirect. Usar allowlist de destinos."
                ));
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
                    notes.add("Directory listing em " + d.getPath() + ": -" + penalty);
                    issues.add(new SecurityIssue(
                            "DIRECTORY_LISTING",
                            "Directory listing habilitado: " + d.getPath(),
                            d.getSeverity(),
                            "Exposição da estrutura de arquivos facilita reconhecimento e acesso a arquivos sensíveis.",
                            "Desabilitar directory listing no servidor web (Options -Indexes no Apache, autoindex off no Nginx)."
                    ));
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
                notes.add("DNS Security (email spoofing risk "
                        + dnsSecurityResult.getEmailSpoofingRisk() + "): -" + penalty);
                // Severidade da issue = nível de risco DNS (CRITICAL/HIGH/MEDIUM)
                // Evita inconsistência entre o que o risco indica e o que a issue exibe
                issues.add(new SecurityIssue(
                        "DNS_EMAIL_SPOOFING",
                        "Risco de email spoofing: " + dnsSecurityResult.getEmailSpoofingRisk(),
                        dnsSecurityResult.getEmailSpoofingRisk(),
                        dnsSecurityResult.getSummary(),
                        "Configure SPF com -all, DMARC com p=reject e DKIM em todos os seletores ativos."
                ));
            }
        }

        // ═══════════════════════════════════════════════════════
        // 16. WAF Detection
        // ═══════════════════════════════════════════════════════
        if (wafDetectionResult != null) {
            if (!wafDetectionResult.isDetected()) {
                score -= 3;
                notes.add("Sem WAF detectado: -3");
                issues.add(new SecurityIssue(
                        "NO_WAF_DETECTED",
                        "Nenhum WAF (Web Application Firewall) detectado",
                        "LOW",
                        "Sem WAF, ataques como SQLi, XSS e brute-force chegam direto ao servidor de aplicação.",
                        "Considere adicionar Cloudflare, AWS WAF ou similar como camada de proteção."
                ));
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
                    notes.add("WAF detectado (" + wafDetectionResult.getProvider()
                            + (probeBlocked ? ", probe bloqueado" : "") + "): +" + bonus);
                } else {
                    // CDN detectado — informativo, sem bônus de score
                    notes.add("CDN detectado (" + wafDetectionResult.getProvider()
                            + "): sem bônus (não é WAF)");
                }
            }
        }


        // ═══════════════════════════════════════════════════════
        // 17. CVE Correlation — apenas CVSS >= 7.0 (HIGH/CRITICAL)
        // POTENCIAL: a correlação parte da versão reportada no banner. Distros
        // frequentemente fazem backport da correção sem alterar o número da versão,
        // então estes achados podem ser falso positivo. Por isso:
        //  - penalidade reduzida (CRITICAL -10, HIGH -6; máx -16, era -25);
        //  - severidade da issue rebaixada um tier (não força risco alto por achado
        //    não confirmado via o severity override);
        //  - rótulo "[Potencial]" + disclaimer pedindo confirmação da versão exata.
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
                    notes.add("CVE potencial tier " + tier + " detectado: -" + penalty);
                }

                String recommendation = "Confirme a versão exata de " + cve.getAffectedSoftware()
                        + " antes de agir — a detecção parte da versão reportada no banner e pode ser"
                        + " falso positivo se o fornecedor/distro aplicou backport da correção sem mudar"
                        + " o número da versão. Se confirmada, atualize para uma versão não afetada."
                        + (cve.getReferenceUrl() != null ? " Ref: " + cve.getReferenceUrl() : "");

                issues.add(new SecurityIssue(
                        "CVE_" + cve.getCveId().replace("-", "_"),
                        "[Potencial] " + cve.getCveId() + " — " + cve.getAffectedSoftware()
                                + " (CVSS " + String.format("%.1f", cve.getCvssScore()) + ")",
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
            notes.add("Path Traversal / LFI (" + pathTraversal.size() + " param(s)): -" + ptPenalty);
        }

        // SSRF penalty — CRITICAL: -15 pts per finding, cap -20
        if (ssrfFindings != null && !ssrfFindings.isEmpty()) {
            int ssrfPenalty = Math.min(ssrfFindings.size() * 15, 20);
            score -= ssrfPenalty;
            notes.add("SSRF (" + ssrfFindings.size() + " param(s)): -" + ssrfPenalty);
        }

        // Host Header Injection penalty — só vetores exploráveis (HIGH/CRITICAL):
        // Location/Set-Cookie. Reflexão só-no-body é LOW (informativa) e NÃO penaliza —
        // é FP comum (canonical/og:url), antes custava -10 indevidamente.
        if (hostHeaderFindings != null && !hostHeaderFindings.isEmpty()) {
            long exploitable = hostHeaderFindings.stream()
                    .filter(h -> "HIGH".equals(h.getSeverity()) || "CRITICAL".equals(h.getSeverity()))
                    .count();
            if (exploitable > 0) {
                int hhPenalty = (int) Math.min(exploitable * 10, 15);
                score -= hhPenalty;
                notes.add("Host Header Injection (" + exploitable + " vetor(es) explorável(is)): -" + hhPenalty);
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
            notes.add("Source Map / Debug Exposure (" + sourceMapFindings.size() + " finding(s)): -" + smPenalty);
        }

        // CRLF Injection penalty — HIGH: -12 pts per finding, cap -18
        if (crlfFindings != null && !crlfFindings.isEmpty()) {
            int crlfPenalty = Math.min(crlfFindings.size() * 12, 18);
            score -= crlfPenalty;
            notes.add("CRLF Injection (" + crlfFindings.size() + " param(s)): -" + crlfPenalty);
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
                issues.add(new SecurityIssue(
                        "JWT_" + jwt.getSeverity(),
                        "JWT inseguro em '" + jwt.getSource() + "' (alg=" + jwt.getAlgorithm() + ")",
                        jwt.getSeverity(),
                        issueDesc,
                        "Usar algoritmo assimetrico (RS256/ES256), adicionar claims exp/iss/aud, "
                        + "nunca usar alg=none em producao."
                ));
            }
            score -= jwtPenalty;
            notes.add("JWT inseguro detectado: -" + jwtPenalty);
        }

        // GraphQL Introspection penalty
        // Introspection habilitada em producao: -5 pts (schema completo exposto)
        // Playground exposto: -8 pts (UI interativa sem auth)
        // Cap: -8 pts total por endpoint
        if (graphQlIntrospection != null && !graphQlIntrospection.isEmpty()) {
            for (GraphQlIntrospectionFinding gql : graphQlIntrospection) {
                int gqlPenalty = gql.isPlaygroundExposed() ? 8 : 5;
                score -= gqlPenalty;
                notes.add("GraphQL " + (gql.isPlaygroundExposed() ? "playground exposto" : "introspection habilitada")
                        + " (" + gql.getEndpoint() + "): -" + gqlPenalty);
                String tc = gql.getTypeCount() > 0 ? " (" + gql.getTypeCount() + " tipos no schema)" : "";
                issues.add(new SecurityIssue(
                        "GRAPHQL_" + (gql.isPlaygroundExposed() ? "PLAYGROUND" : "INTROSPECTION"),
                        "GraphQL " + (gql.isPlaygroundExposed() ? "playground publico" : "introspection habilitada")
                                + " em " + gql.getEndpoint() + tc,
                        gql.getSeverity(),
                        gql.isPlaygroundExposed()
                                ? "Interface GraphQL interativa acessivel sem autenticacao — permite explorar e executar queries na API."
                                : "Introspection habilitada em producao — expoe schema completo: queries, mutations, tipos e campos.",
                        "Desabilitar introspection em producao (ex: spring.graphql.schema.introspection.enabled=false). "
                        + "Restringir acesso ao playground a ambientes de desenvolvimento."
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
            notes.add("API docs expostos (" + apiDocsExposure.size() + " endpoint(s)): -" + apiPenalty);
            for (ApiDocsExposureFinding f : apiDocsExposure) {
                String issueSev = "HIGH".equals(f.getSeverity()) ? "MEDIUM" : "LOW";
                issues.add(new SecurityIssue(
                        "API_DOCS_" + f.getType(),
                        "Documentacao de API exposta: " + f.getPath(),
                        issueSev,
                        f.getDescription(),
                        "Restringir acesso a documentacao de API em producao via autenticacao " +
                        "ou remover os endpoints /swagger-ui, /api-docs, /openapi.json."
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

    /**
     * Rebaixa a severidade em um tier. Usado para achados POTENCIAIS (ex: CVE por
     * versão de banner) — evita que um achado não confirmado force o risco global
     * para cima via o severity override.
     */
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
                    notes.add("HSTS ausente: -10");
                    issues.add(new SecurityIssue("HSTS_MISSING",
                            "Strict-Transport-Security ausente", "HIGH",
                            "Ataques downgrade para HTTP são possíveis.",
                            "Adicionar: Strict-Transport-Security: max-age=31536000; includeSubDomains"));
                    yield score - 10;
                } else if (status.startsWith("WEAK")) {
                    notes.add("HSTS fraco: -5");
                    issues.add(new SecurityIssue("HSTS_WEAK",
                            "Strict-Transport-Security fraco", "MEDIUM",
                            "Configuração incompleta reduz a proteção.",
                            "Garantir max-age >= 2592000 e considerar includeSubDomains."));
                    yield score - 5;
                }
                yield score;
            }

            case "X-Content-Type-Options" -> {
                if (status.startsWith("MISSING")) {
                    notes.add("X-Content-Type-Options ausente: -5");
                    issues.add(new SecurityIssue("CONTENT_TYPE_MISSING",
                            "X-Content-Type-Options ausente", "MEDIUM",
                            "Pode permitir MIME sniffing.",
                            "Adicionar: X-Content-Type-Options: nosniff"));
                    yield score - 5;
                }
                yield score;
            }

            case "Content-Security-Policy" -> {
                if (status.startsWith("MISSING")) {
                    notes.add("CSP ausente: -10");
                    issues.add(new SecurityIssue("CSP_MISSING",
                            "Content-Security-Policy ausente", "HIGH",
                            "Sem barreira contra injeção de scripts externos.",
                            "Implementar CSP com default-src 'self' como base."));
                    yield score - 10;
                } else if (status.startsWith("WEAK")) {
                    notes.add("CSP fraca (unsafe-inline/eval): -5");
                    issues.add(new SecurityIssue("CSP_WEAK",
                            "Content-Security-Policy fraca", "MEDIUM",
                            "unsafe-inline ou unsafe-eval anulam a proteção contra XSS.",
                            "Remover 'unsafe-inline' e 'unsafe-eval'. Usar nonces ou hashes."));
                    yield score - 5;
                }
                yield score;
            }

            case "X-Frame-Options" -> {
                if (status.startsWith("MISSING")) {
                    notes.add("X-Frame-Options ausente: -5");
                    issues.add(new SecurityIssue("XFRAME_MISSING",
                            "X-Frame-Options ausente", "MEDIUM",
                            "Site pode ser embutido em iframes — risco de clickjacking.",
                            "Adicionar X-Frame-Options: DENY ou usar frame-ancestors no CSP."));
                    yield score - 5;
                }
                yield score;
            }

            case "Referrer-Policy" -> {
                if (status.startsWith("MISSING")) {
                    notes.add("Referrer-Policy ausente: -5");
                    issues.add(new SecurityIssue("REFERRER_POLICY_MISSING",
                            "Referrer-Policy ausente", "LOW",
                            "URLs internas podem vazar para sites externos via header Referer.",
                            "Adicionar: Referrer-Policy: strict-origin-when-cross-origin"));
                    yield score - 5;
                } else if (status.startsWith("WEAK")) {
                    notes.add("Referrer-Policy insegura: -5");
                    issues.add(new SecurityIssue("REFERRER_POLICY_WEAK",
                            "Referrer-Policy insegura", "MEDIUM",
                            "unsafe-url vaza URLs completas incluindo query strings.",
                            "Usar strict-origin-when-cross-origin ou no-referrer."));
                    yield score - 5;
                }
                yield score;
            }

            case "Permissions-Policy" -> {
                if (status.startsWith("MISSING")) {
                    notes.add("Permissions-Policy ausente: -3");
                    issues.add(new SecurityIssue("PERMISSIONS_POLICY_MISSING",
                            "Permissions-Policy ausente", "LOW",
                            "Sem restrição de APIs de browser (câmera, microfone, geolocalização).",
                            "Adicionar Permissions-Policy restringindo features não usadas."));
                    yield score - 3;
                }
                yield score;
            }

            default -> score;
        };
    }
}