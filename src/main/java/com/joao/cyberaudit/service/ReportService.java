package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.*;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class ReportService {

    public String generateReport(ScanResult r) {
        StringBuilder s = new StringBuilder();

        // ── Overview ──────────────────────────────────────
        s.append("== Overview ==\n");
        s.append("Generated:    ").append(LocalDateTime.now()).append("\n");
        s.append("URL analyzed: ").append(r.getUrl()).append("\n");
        s.append("Final URL:    ").append(r.getFinalUrl()).append("\n");
        s.append("HTTP Status:  ").append(r.getHttpStatus()).append("\n");
        s.append("Score:        ").append(r.getScore().getScore())
                .append("/100 (").append(r.getScore().getRiskLevel()).append(")\n\n");
        s.append("Scan type:    ").append(r.isActiveMode() ? "ACTIVE" : "PASSIVE").append("\n");


        // ── Transport Security ─────────────────────────────
        s.append("== Transport Security ==\n");
        if (r.getSslInfo() != null) {
            s.append("HTTPS supported:   ").append(r.getSslInfo().isHttps()).append("\n");
            s.append("Certificate valid: ").append(r.getSslInfo().isValid()).append("\n");
            s.append("Expiration:        ").append(r.getSslInfo().getExpirationDate()).append("\n");
            s.append("Days remaining:    ").append(r.getSslInfo().getDaysRemaining()).append("\n");
        }
        s.append("Forces redirect:   ").append(r.isRedirectsToHttps()).append("\n");
        if (r.getTlsDetails() != null) {
            TlsDetails tls = r.getTlsDetails();
            s.append("TLS Protocol:  ").append(tls.getNegotiatedProtocol()).append("\n");
            s.append("Cipher Suite:  ").append(tls.getCipherSuite()).append("\n");
            s.append("Weak Protocol: ").append(tls.isWeakProtocol()).append("\n");
            if (tls.getMessage() != null && !tls.getMessage().isBlank())
                s.append("TLS Message:   ").append(tls.getMessage()).append("\n");
        }
        s.append("\n");

        // ── Security Headers ───────────────────────────────
        s.append("== Security Headers ==\n");
        if (r.getHeaders() != null && !r.getHeaders().isEmpty()) {
            r.getHeaders().forEach((k, v) ->
                    s.append(String.format("  %-35s %s%n", k, v)));
        }
        s.append("Server version exposed: ").append(r.isServerVersionExposed()).append("\n\n");

        // ── CORS ──────────────────────────────────────────
        if (r.getCorsResult() != null && r.getCorsResult().isTested()) {
            CorsResult c = r.getCorsResult();
            boolean corsIssue = c.isWildcardOrigin() || c.isReflectsOrigin()
                    || c.isCredentialsAllowed() || c.isNullOriginAccepted();
            if (corsIssue) {
                s.append("== CORS Analysis ==\n");
                s.append("ACAO value:      ").append(c.getAllowOriginValue()).append("\n");
                s.append("Wildcard origin: ").append(c.isWildcardOrigin()).append("\n");
                s.append("Reflects origin: ").append(c.isReflectsOrigin()).append("\n");
                s.append("Credentials:     ").append(c.isCredentialsAllowed()).append("\n");
                s.append("Null origin:     ").append(c.isNullOriginAccepted()).append("\n");
                if (c.getMessage() != null)
                    s.append("Assessment:      ").append(c.getMessage()).append("\n");
                s.append("\n");
            }
        }

        // ── Cookies ───────────────────────────────────────
        if (r.getCookieIssues() != null && !r.getCookieIssues().isEmpty()) {
            s.append("== Cookie Security ==\n");
            for (CookieFinding cf : r.getCookieIssues()) {
                s.append("  [").append(cf.getRisk()).append("] ").append(cf.getName()).append("\n");
                s.append("    HttpOnly: ").append(cf.isHttpOnly())
                        .append(" | Secure: ").append(cf.isSecure())
                        .append(" | SameSite: ").append(cf.getSameSite()).append("\n");
                if (cf.getIssues() != null && !cf.getIssues().isBlank())
                    s.append("    Issues: ").append(cf.getIssues()).append("\n");
            }
            s.append("\n");
        }

        // ── HTTP Methods ──────────────────────────────────
        if (r.getDangerousHttpMethods() != null && !r.getDangerousHttpMethods().isEmpty()) {
            s.append("== Dangerous HTTP Methods ==\n");
            for (HttpMethodFinding m : r.getDangerousHttpMethods()) {
                s.append("  [").append(m.getSeverity()).append("] ")
                        .append(m.getMethod())
                        .append("  (HTTP ").append(m.getStatusCode()).append(")\n");
                if (m.getRisk() != null && !m.getRisk().isBlank())
                    s.append("    Risk: ").append(m.getRisk()).append("\n");
            }
            s.append("\n");
        }

        // ── Sensitive Files ───────────────────────────────
        if (r.getSensitiveFiles() != null && !r.getSensitiveFiles().isEmpty()) {
            List<SensitiveFileFinding> exposed = r.getSensitiveFiles().stream()
                    .filter(f -> "EXPOSED".equals(f.getExposure()))
                    .toList();
            if (!exposed.isEmpty()) {
                s.append("== Sensitive Files ==\n");
                for (SensitiveFileFinding f : exposed) {
                    s.append("  [").append(f.getSeverity()).append("] ")
                            .append(f.getPath())
                            .append("  HTTP ").append(f.getStatusCode()).append("\n");
                    if (f.getContentPreview() != null && !f.getContentPreview().isBlank())
                        s.append("    Preview: ").append(f.getContentPreview()).append("\n");
                }
                s.append("\n");
            }
        }

        // ── robots.txt ────────────────────────────────────
        if (r.getSensitiveRobotsPaths() != null && !r.getSensitiveRobotsPaths().isEmpty()) {
            s.append("== robots.txt Sensitive Paths ==\n");
            r.getSensitiveRobotsPaths().forEach(p ->
                    s.append("  Disallow: ").append(p).append("\n"));
            s.append("\n");
        }

        // ── Open Redirect ─────────────────────────────────
        if (r.getOpenRedirectFindings() != null && !r.getOpenRedirectFindings().isEmpty()) {
            List<OpenRedirectFinding> vuln = r.getOpenRedirectFindings().stream()
                    .filter(OpenRedirectFinding::isVulnerable)
                    .toList();
            if (!vuln.isEmpty()) {
                s.append("== Open Redirect ==\n");
                for (OpenRedirectFinding f : vuln) {
                    s.append("  [").append(f.getSeverity()).append("] ")
                            .append(f.getTestedUrl()).append("\n");
                    if (f.getRedirectedTo() != null && !f.getRedirectedTo().isBlank())
                        s.append("    Redirected to: ").append(f.getRedirectedTo()).append("\n");
                    if (f.getParameter() != null && !f.getParameter().isBlank())
                        s.append("    Parameter: ").append(f.getParameter()).append("\n");
                }
                s.append("\n");
            }
        }

        // ── Directory Listing ─────────────────────────────
        if (r.getDirectoryListingFindings() != null && !r.getDirectoryListingFindings().isEmpty()) {
            List<DirectoryListingFinding> enabled = r.getDirectoryListingFindings().stream()
                    .filter(DirectoryListingFinding::isListingEnabled)
                    .toList();
            if (!enabled.isEmpty()) {
                s.append("== Directory Listing ==\n");
                for (DirectoryListingFinding f : enabled) {
                    s.append("  [").append(f.getSeverity()).append("] ")
                            .append(f.getPath())
                            .append("  HTTP ").append(f.getStatusCode()).append("\n");
                    if (f.getEvidence() != null && !f.getEvidence().isBlank())
                        s.append("    Evidence: ").append(f.getEvidence()).append("\n");
                }
                s.append("\n");
            }
        }

        // ── DNS Security ──────────────────────────────────
        if (r.getDnsSecurityResult() != null) {
            DnsSecurityResult dns = r.getDnsSecurityResult();
            boolean dnsHasFindings = dns.getSpfPolicy() != null || dns.getDmarcPolicy() != null;
            if (dnsHasFindings) {
                s.append("== DNS Security (Reconnaissance) ==\n");
                if (dns.getSpfPolicy() != null) {
                    s.append("  SPF:   [").append(dns.getSpfPolicy()).append("]");
                    if (dns.getSpfRecord() != null && !dns.getSpfRecord().isBlank())
                        s.append("  ").append(dns.getSpfRecord());
                    s.append("\n");
                } else {
                    s.append("  SPF:   [MISSING]\n");
                }
                if (dns.getDmarcPolicy() != null) {
                    s.append("  DMARC: [").append(dns.getDmarcPolicy()).append("]");
                    if (dns.getDmarcRecord() != null && !dns.getDmarcRecord().isBlank())
                        s.append("  ").append(dns.getDmarcRecord());
                    s.append("\n");
                } else {
                    s.append("  DMARC: [MISSING]\n");
                }
                if (dns.isDkimHintFound()) {
                    s.append("  DKIM:  [FOUND]");
                    if (dns.getDkimSelector() != null)
                        s.append("  selector=").append(dns.getDkimSelector());
                    s.append("\n");
                } else {
                    s.append("  DKIM:  [NOT FOUND]\n");
                }
                if (dns.isCaaPresent()) {
                    s.append("  CAA:   [PRESENT]");
                    if (dns.getCaaRecord() != null && !dns.getCaaRecord().isBlank())
                        s.append("  ").append(dns.getCaaRecord());
                    s.append("\n");
                } else {
                    s.append("  CAA:   [MISSING]\n");
                }
                if (dns.getMxRecords() != null && !dns.getMxRecords().isEmpty()) {
                    s.append("  MX:    ").append(String.join(", ", dns.getMxRecords())).append("\n");
                }
                if (dns.getEmailSpoofingRisk() != null)
                    s.append("  Email Spoofing Risk: ").append(dns.getEmailSpoofingRisk()).append("\n");
                if (dns.getSummary() != null && !dns.getSummary().isBlank())
                    s.append("  Summary: ").append(dns.getSummary()).append("\n");
                s.append("\n");
            }
        }

        // ── WAF Detection ─────────────────────────────────
        if (r.getWafDetectionResult() != null) {
            WafDetectionResult waf = r.getWafDetectionResult();
            s.append("== WAF / CDN Detection ==\n");
            if (waf.isDetected() && waf.getProvider() != null) {
                s.append("  WAF/CDN: ").append(waf.getProvider());
                if (waf.getConfidence() != null)
                    s.append("  (confidence: ").append(waf.getConfidence()).append(")");
                s.append("\n");
            } else {
                s.append("  No WAF/CDN detected.\n");
            }
            if ("BLOCKED".equals(waf.getProbeResponse()))
                s.append("  Malicious probe: BLOCKED\n");
            if (waf.getEvidence() != null && !waf.getEvidence().isBlank())
                s.append("  Evidence: ").append(waf.getEvidence()).append("\n");
            s.append("\n");
        }

        // ── security.txt ──────────────────────────────────
        if (r.isSecurityTxtPresent()) {
            s.append("== security.txt ==\n");
            s.append("  Present: true\n");
            if (r.getSecurityTxtContact() != null && !r.getSecurityTxtContact().isBlank())
                s.append("  Contact: ").append(r.getSecurityTxtContact()).append("\n");
            s.append("\n");
        }

        // ── Application Security (somente com findings) ───
        if (r.isActiveMode()) {
            boolean appHasFindings = r.isInputSurfaceDetected()
                    || r.isDbErrorLeakageSuspected()
                    || r.isReflectedXssSuspected();
            if (appHasFindings) {
                s.append("== Application Security ==\n");
                if (r.isInputSurfaceDetected())
                    s.append("  Input surface detected.\n");
                if (r.isDbErrorLeakageSuspected())
                    s.append("  DB error leakage suspected.\n");
                if (r.isReflectedXssSuspected())
                    s.append("  Reflected XSS suspected.\n");
                s.append("\n");
            }
        }

        // ── Network Exposure ──────────────────────────────
        if (r.getOpenPorts() != null && !r.getOpenPorts().isEmpty()) {
            s.append("== Network Exposure ==\n");
            for (PortFinding p : r.getOpenPorts()) {
                s.append("- Port ").append(p.getPort())
                        .append(" (").append(p.getService()).append(")")
                        .append("  state=").append(p.getState())
                        .append("  severity=").append(p.getSeverity()).append("\n");
                s.append("  Latency: ").append(p.getLatencyMs()).append("ms\n");
                if (p.getEvidence() != null && !p.getEvidence().isBlank())
                    s.append("  Evidence: ").append(p.getEvidence()).append("\n");
                if (p.getImpact() != null && !p.getImpact().isBlank())
                    s.append("  Impact: ").append(p.getImpact()).append("\n");
                if (p.getRecommendation() != null && !p.getRecommendation().isBlank())
                    s.append("  Recommendation: ").append(p.getRecommendation()).append("\n");
                s.append("\n");
            }
        }

        // ── Issues Summary ────────────────────────────────
        if (r.getScore() != null && r.getScore().getIssues() != null
                && !r.getScore().getIssues().isEmpty()) {
            s.append("== Issues Summary ==\n");
            for (SecurityIssue issue : r.getScore().getIssues()) {
                s.append("\n- [").append(issue.getSeverity()).append("] ")
                        .append(issue.getTitle()).append("\n");
                if (issue.getImpact() != null && !issue.getImpact().isBlank())
                    s.append("  Impact:         ").append(issue.getImpact()).append("\n");
                if (issue.getRecommendation() != null && !issue.getRecommendation().isBlank())
                    s.append("  Recommendation: ").append(issue.getRecommendation()).append("\n");
            }
            s.append("\n");
        }

        return s.toString();
    }
}