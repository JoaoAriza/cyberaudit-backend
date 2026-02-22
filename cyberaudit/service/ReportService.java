package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.PortFinding;
import com.joao.cyberaudit.model.ScanResult;
import com.joao.cyberaudit.model.SecurityIssue;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
public class ReportService {

    public String generateReport(ScanResult r) {

        StringBuilder report = new StringBuilder();

        report.append("\n=========== WEB SECURITY REPORT ===========\n\n");

        // ===== OVERVIEW =====
        report.append("== Overview ==\n");
        report.append("Generated: ").append(LocalDateTime.now()).append("\n");
        report.append("URL analyzed: ").append(r.getUrl()).append("\n");
        report.append("Final URL: ").append(r.getFinalUrl()).append("\n");
        report.append("HTTP Status: ").append(r.getHttpStatus()).append("\n");
        report.append("Score: ")
                .append(r.getScore().getScore())
                .append("/100 (")
                .append(r.getScore().getRiskLevel())
                .append(")\n\n");

        // ===== TRANSPORT SECURITY =====
        report.append("== Transport Security ==\n");
        report.append("HTTPS supported: ").append(r.getSslInfo().isHttps()).append("\n");
        report.append("Certificate valid: ").append(r.getSslInfo().isValid()).append("\n");
        report.append("Expiration: ").append(r.getSslInfo().getExpirationDate()).append("\n");
        report.append("Days remaining: ").append(r.getSslInfo().getDaysRemaining()).append("\n");
        report.append("Forces HTTPS redirect: ").append(r.isRedirectsToHttps()).append("\n\n");

        // ===== APPLICATION SECURITY =====
        report.append("== Application Security ==\n");
        report.append("Active mode: ").append(r.isActiveMode()).append("\n");
        report.append("Input surface detected: ").append(r.isInputSurfaceDetected()).append("\n");
        report.append("DB error leakage suspected: ").append(r.isDbErrorLeakageSuspected()).append("\n");
        report.append("XSS probe executed: ").append(r.isXssProbePerformed()).append("\n");
        report.append("Reflected XSS suspected: ").append(r.isReflectedXssSuspected()).append("\n\n");

        // ===== NETWORK EXPOSURE =====
        report.append("== Network Exposure (Active Mode) ==\n");
        if (r.getOpenPorts() == null || r.getOpenPorts().isEmpty()) {
            report.append("No common open ports detected or active mode disabled.\n\n");
        } else {
            for (PortFinding p : r.getOpenPorts()) {
                report.append("- Port ").append(p.getPort())
                        .append(" (").append(p.getService()).append(")")
                        .append(" [").append(p.getSeverity()).append("]\n");
                report.append("  Impact: ").append(p.getImpact()).append("\n");
                report.append("  Recommendation: ").append(p.getRecommendation()).append("\n\n");
            }
        }

        // ===== ISSUES SUMMARY =====
        report.append("== Issues Summary ==\n");
        if (r.getScore().getIssues().isEmpty()) {
            report.append("No significant issues detected.\n");
        } else {
            for (SecurityIssue issue : r.getScore().getIssues()) {
                report.append("\n- ").append(issue.getTitle());
                report.append("\n  Severity: ").append(issue.getSeverity());
                report.append("\n  Impact: ").append(issue.getImpact());
                report.append("\n  Recommendation: ").append(issue.getRecommendation());
                report.append("\n");
            }
        }

        report.append("\n==========================================\n");

        return report.toString();
    }
}