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
            DnsSecurityResult dnsSecurityResult
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
                score -= 15;
                notes.add("Erro ao buscar headers: -15");
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
        if (activeMode && openPorts != null) {
            for (PortFinding p : openPorts) {
                if ("HIGH".equals(p.getSeverity())) {
                    score -= 10;
                    notes.add("Porta de risco aberta (" + p.getPort() + "/" + p.getService() + "): -10");
                } else if ("MEDIUM".equals(p.getSeverity())) {
                    score -= 5;
                    notes.add("Porta aberta exposta (" + p.getPort() + "/" + p.getService() + "): -5");
                }
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
                issues.add(new SecurityIssue(
                        "DNS_EMAIL_SPOOFING",
                        "Risco de email spoofing: " + dnsSecurityResult.getEmailSpoofingRisk(),
                        penalty >= 15 ? "HIGH" : "MEDIUM",
                        dnsSecurityResult.getSummary(),
                        "Configure SPF com -all, DMARC com p=reject e DKIM em todos os seletores ativos."
                ));
            }
        }

        score = Math.max(0, score);
        RiskLevel risk = score >= 80 ? RiskLevel.SECURE
                : score >= 50 ? RiskLevel.WARNING
                : RiskLevel.CRITICAL;

        return new ScoreResult(score, risk, notes, issues);
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