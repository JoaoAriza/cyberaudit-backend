package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.*;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
public class ReportService {

    public String generateReport(ScanResult r) {
        StringBuilder s = new StringBuilder();

        s.append("\n=========== WEB SECURITY REPORT ===========\n\n");

        // ── Overview ──────────────────────────────────────
        s.append("== Overview ==\n");
        s.append("Generated:    ").append(LocalDateTime.now()).append("\n");
        s.append("URL analyzed: ").append(r.getUrl()).append("\n");
        s.append("Final URL:    ").append(r.getFinalUrl()).append("\n");
        s.append("HTTP Status:  ").append(r.getHttpStatus()).append("\n");
        s.append("Score:        ").append(r.getScore().getScore())
                .append("/100 (").append(r.getScore().getRiskLevel()).append(")\n\n");

        // ── Transport Security ─────────────────────────────
        s.append("== Transport Security ==\n");
        s.append("HTTPS supported:   ").append(r.getSslInfo().isHttps()).append("\n");
        s.append("Certificate valid: ").append(r.getSslInfo().isValid()).append("\n");
        s.append("Expiration:        ").append(r.getSslInfo().getExpirationDate()).append("\n");
        s.append("Days remaining:    ").append(r.getSslInfo().getDaysRemaining()).append("\n");
        s.append("Forces redirect:   ").append(r.isRedirectsToHttps()).append("\n");

        if (r.getTlsDetails() != null) {
            TlsDetails tls = r.getTlsDetails();
            s.append("TLS Protocol:      ").append(tls.getNegotiatedProtocol()).append("\n");
            s.append("Cipher Suite:      ").append(tls.getCipherSuite()).append("\n");
            s.append("Weak Protocol:     ").append(tls.isWeakProtocol()).append("\n");
            s.append("TLS Message:       ").append(tls.getMessage()).append("\n");
        }
        s.append("\n");

        // ── Security Headers ───────────────────────────────
        s.append("== Security Headers ==\n");
        if (r.getHeaders() != null) {
            r.getHeaders().forEach((k, v) ->
                    s.append(String.format("  %-35s %s%n", k, v)));
        }
        s.append("Server version exposed: ").append(r.isServerVersionExposed()).append("\n\n");

        // ── CORS ──────────────────────────────────────────
        s.append("== CORS Analysis ==\n");
        if (r.getCorsResult() != null && r.getCorsResult().isTested()) {
            CorsResult c = r.getCorsResult();
            s.append("ACAO value:       ").append(c.getAllowOriginValue()).append("\n");
            s.append("Wildcard origin:  ").append(c.isWildcardOrigin()).append("\n");
            s.append("Reflects origin:  ").append(c.isReflectsOrigin()).append("\n");
            s.append("Credentials:      ").append(c.isCredentialsAllowed()).append("\n");
            s.append("Null origin:      ").append(c.isNullOriginAccepted()).append("\n");
            s.append("Assessment:       ").append(c.getMessage()).append("\n");
        } else {
            s.append("CORS probe not executed.\n");
        }
        s.append("\n");

        // ── Cookies ───────────────────────────────────────
        s.append("== Cookie Security ==\n");
        if (r.getCookieIssues() == null || r.getCookieIssues().isEmpty()) {
            s.append("No cookie issues detected.\n");
        } else {
            for (CookieFinding cf : r.getCookieIssues()) {
                s.append("  [").append(cf.getRisk()).append("] ").append(cf.getName()).append("\n");
                s.append("    HttpOnly: ").append(cf.isHttpOnly())
                        .append(" | Secure: ").append(cf.isSecure())
                        .append(" | SameSite: ").append(cf.getSameSite()).append("\n");
                s.append("    Issues: ").append(cf.getIssues()).append("\n");
            }
        }
        s.append("\n");

        // ── robots.txt ────────────────────────────────────
        s.append("== robots.txt Sensitive Paths ==\n");
        if (r.getSensitiveRobotsPaths() == null || r.getSensitiveRobotsPaths().isEmpty()) {
            s.append("No sensitive paths found.\n");
        } else {
            r.getSensitiveRobotsPaths().forEach(p ->
                    s.append("  Disallow: ").append(p).append("\n"));
        }
        s.append("\n");

        // ── Application Security ──────────────────────────
        s.append("== Application Security ==\n");
        s.append("Active mode:             ").append(r.isActiveMode()).append("\n");
        s.append("Input surface detected:  ").append(r.isInputSurfaceDetected()).append("\n");
        s.append("DB error leakage:        ").append(r.isDbErrorLeakageSuspected()).append("\n");
        s.append("XSS probe executed:      ").append(r.isXssProbePerformed()).append("\n");
        s.append("Reflected XSS suspected: ").append(r.isReflectedXssSuspected()).append("\n\n");

        // ── Network Exposure ──────────────────────────────
        s.append("== Network Exposure (Active Mode) ==\n");
        if (r.getOpenPorts() == null || r.getOpenPorts().isEmpty()) {
            s.append("No open ports detected or active mode disabled.\n\n");
        } else {
            for (PortFinding p : r.getOpenPorts()) {
                s.append("- Port ").append(p.getPort())
                        .append(" (").append(p.getService()).append(")")
                        .append("  state=").append(p.getState())
                        .append("  severity=").append(p.getSeverity()).append("\n");
                s.append("  Latency: ").append(p.getLatencyMs()).append("ms\n");
                if (p.getEvidence() != null && !p.getEvidence().isBlank())
                    s.append("  Evidence: ").append(p.getEvidence()).append("\n");
                s.append("  Impact: ").append(p.getImpact()).append("\n");
                s.append("  Recommendation: ").append(p.getRecommendation()).append("\n\n");
            }
        }

        // ── Issues Summary ────────────────────────────────
        s.append("== Issues Summary ==\n");
        if (r.getScore().getIssues().isEmpty()) {
            s.append("No significant issues detected.\n");
        } else {
            for (SecurityIssue issue : r.getScore().getIssues()) {
                s.append("\n- [").append(issue.getSeverity()).append("] ")
                        .append(issue.getTitle()).append("\n");
                s.append("  Impact:         ").append(issue.getImpact()).append("\n");
                s.append("  Recommendation: ").append(issue.getRecommendation()).append("\n");
            }
        }

        s.append("\n==========================================\n");
        return s.toString();
    }
}