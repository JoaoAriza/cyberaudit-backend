package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.RiskLevel;
import com.joao.cyberaudit.model.ScanRecord;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class BadgeService {

    private final ScanHistoryService scanHistoryService;

    public BadgeService(ScanHistoryService scanHistoryService) {
        this.scanHistoryService = scanHistoryService;
    }

    /**
     * Gera badge lendo do histórico de scans (fallback padrão).
     */
    public String generateBadge(String host, String style) {
        List<ScanRecord> records = scanHistoryService.findByHost(host, 1);
        if (records.isEmpty()) return buildNotScannedBadge(host, style);
        ScanRecord latest = records.get(0);
        return buildBadge(host, latest.getScore(), latest.getRiskLevel(), style);
    }

    /**
     * Gera badge com score e riskLevel passados diretamente (resultado atual do scan).
     * Usado pelo frontend logo após um scan completar — evita lag do histórico.
     */
    public String generateBadge(String host, int score, String riskLevel, String style) {
        RiskLevel risk;
        try {
            risk = RiskLevel.valueOf(riskLevel.toUpperCase());
        } catch (Exception e) {
            risk = score >= 85 ? RiskLevel.SECURE
                 : score >= 70 ? RiskLevel.LOW
                 : score >= 45 ? RiskLevel.MEDIUM
                 : score >= 20 ? RiskLevel.HIGH
                 : RiskLevel.CRITICAL;
        }
        return buildBadge(host, score, risk, style);
    }

    private String buildBadge(String host, int score, RiskLevel risk, String style) {
        String color      = colorFor(risk);
        String labelColor = "#555";
        String label      = "cyberaudit";
        String value      = score + "/100";

        return switch (style) {
            case "shield" -> buildShieldStyle(label, value, color, labelColor);
            case "flat"   -> buildFlatStyle(label, value, color, labelColor);
            default       -> buildClassicStyle(label, value, color, labelColor);
        };
    }

    private String buildNotScannedBadge(String host, String style) {
        return buildFlatStyle("cyberaudit", "not scanned", "#9f9f9f", "#555");
    }

    private String buildClassicStyle(String label, String value,
                                     String rightColor, String leftColor) {
        int labelWidth = textWidth(label) + 20;
        int valueWidth = textWidth(value) + 20;
        int totalWidth = labelWidth + valueWidth;
        int height     = 20;
        int cy         = 11;

        return """
                <svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d">
                  <linearGradient id="s" x2="0" y2="100%%">
                    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
                    <stop offset="1" stop-opacity=".1"/>
                  </linearGradient>
                  <clipPath id="r">
                    <rect width="%d" height="%d" rx="3" fill="#fff"/>
                  </clipPath>
                  <g clip-path="url(#r)">
                    <rect width="%d" height="%d" fill="%s"/>
                    <rect x="%d" width="%d" height="%d" fill="%s"/>
                    <rect width="%d" height="%d" fill="url(#s)"/>
                  </g>
                  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
                    <text x="%d" y="%d" fill="#010101" fill-opacity=".3">%s</text>
                    <text x="%d" y="%d">%s</text>
                    <text x="%d" y="%d" fill="#010101" fill-opacity=".3">%s</text>
                    <text x="%d" y="%d">%s</text>
                  </g>
                </svg>
                """.formatted(
                totalWidth, height,
                totalWidth, height,
                labelWidth, height, leftColor,
                labelWidth, valueWidth, height, rightColor,
                totalWidth, height,
                labelWidth / 2, cy + 1, label,
                labelWidth / 2, cy, label,
                labelWidth + valueWidth / 2, cy + 1, value,
                labelWidth + valueWidth / 2, cy, value
        );
    }

    private String buildFlatStyle(String label, String value,
                                  String rightColor, String leftColor) {
        int labelWidth = textWidth(label) + 20;
        int valueWidth = textWidth(value) + 20;
        int totalWidth = labelWidth + valueWidth;
        int height     = 20;
        int cy         = 14;

        return """
                <svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d">
                  <rect width="%d" height="%d" rx="3" fill="%s"/>
                  <rect x="%d" width="%d" height="%d" rx="3" fill="%s"/>
                  <rect x="%d" width="4" height="%d" fill="%s"/>
                  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
                    <text x="%d" y="%d">%s</text>
                    <text x="%d" y="%d">%s</text>
                  </g>
                </svg>
                """.formatted(
                totalWidth, height,
                totalWidth, height, leftColor,
                labelWidth, valueWidth, height, rightColor,
                labelWidth, height, rightColor,
                labelWidth / 2, cy, label,
                labelWidth + valueWidth / 2, cy, value
        );
    }

    private String buildShieldStyle(String label, String value,
                                    String rightColor, String leftColor) {
        int labelWidth = textWidth(label) + 30; // +30 para o espaço do ícone
        int valueWidth = textWidth(value) + 20;
        int totalWidth = labelWidth + valueWidth;
        int height     = 20;
        int cy         = 14;

        String shieldPath = "M5,3 L11,3 L11,10 C11,13 8,15 8,15 C8,15 5,13 5,10 Z";

        return """
                <svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d">
                  <rect width="%d" height="%d" rx="3" fill="%s"/>
                  <rect x="%d" width="%d" height="%d" rx="3" fill="%s"/>
                  <rect x="%d" width="4" height="%d" fill="%s"/>
                  <path d="%s" fill="#fff" fill-opacity="0.8" transform="translate(2,2)"/>
                  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
                    <text x="%d" y="%d">%s</text>
                    <text x="%d" y="%d">%s</text>
                  </g>
                </svg>
                """.formatted(
                totalWidth, height,
                totalWidth, height, leftColor,
                labelWidth, valueWidth, height, rightColor,
                labelWidth, height, rightColor,
                shieldPath,
                labelWidth / 2 + 5, cy, label,
                labelWidth + valueWidth / 2, cy, value
        );
    }

    private String colorFor(RiskLevel risk) {
        return switch (risk) {
            case SECURE            -> "#4c9a2a"; // verde
            case LOW               -> "#3b9eff"; // azul
            case MEDIUM, WARNING   -> "#d4a017"; // amarelo (WARNING = legado)
            case HIGH              -> "#ff6b35"; // laranja
            case CRITICAL          -> "#c0392b"; // vermelho
        };
    }

    private int textWidth(String text) {
        int width = 0;
        for (char c : text.toCharArray()) {
            if ("WMmwD".indexOf(c) >= 0)      width += 9;
            else if ("IiljtfJ1 ".indexOf(c) >= 0) width += 5;
            else                                   width += 7;
        }
        return width;
    }
}