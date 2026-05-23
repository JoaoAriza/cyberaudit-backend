package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.ScanResult;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.graphics.color.PDColor;
import org.apache.pdfbox.pdmodel.graphics.color.PDDeviceRGB;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Service
public class PdfReportService {

    private static final float MARGIN      = 50f;
    private static final float LINE_HEIGHT = 14f;
    private static final float PAGE_HEIGHT = PDRectangle.A4.getHeight();
    private static final float PAGE_WIDTH  = PDRectangle.A4.getWidth();

    public byte[] generatePdf(ScanResult result, String reportText) {
        try (PDDocument doc = new PDDocument();
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {

            // PDFBox 2.x — fontes via constantes estáticas (não Standard14Fonts)
            PDType1Font fontBold   = PDType1Font.HELVETICA_BOLD;
            PDType1Font fontNormal = PDType1Font.HELVETICA;
            PDType1Font fontMono   = PDType1Font.COURIER;

            PDPage page = new PDPage(PDRectangle.A4);
            doc.addPage(page);
            PDPageContentStream cs = new PDPageContentStream(doc, page);

            float y = PAGE_HEIGHT - MARGIN;

            // ── Cabeçalho ─────────────────────────────────────────────────────
            cs.setNonStrokingColor(new PDColor(
                    new float[]{0.05f, 0.07f, 0.10f}, PDDeviceRGB.INSTANCE));
            cs.addRect(0, PAGE_HEIGHT - 80, PAGE_WIDTH, 80);
            cs.fill();

            cs.beginText();
            cs.setNonStrokingColor(new PDColor(
                    new float[]{0f, 0.83f, 0.63f}, PDDeviceRGB.INSTANCE));
            cs.setFont(fontBold, 18);
            cs.newLineAtOffset(MARGIN, PAGE_HEIGHT - 40);
            cs.showText("CYBERAUDIT");
            cs.endText();

            cs.beginText();
            cs.setNonStrokingColor(new PDColor(
                    new float[]{0.72f, 0.80f, 0.87f}, PDDeviceRGB.INSTANCE));
            cs.setFont(fontNormal, 11);
            cs.newLineAtOffset(MARGIN, PAGE_HEIGHT - 58);
            cs.showText("Web Security Report");
            cs.endText();

            String date = LocalDateTime.now()
                    .format(DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm"));
            cs.beginText();
            cs.setNonStrokingColor(new PDColor(
                    new float[]{0.35f, 0.48f, 0.59f}, PDDeviceRGB.INSTANCE));
            cs.setFont(fontNormal, 9);
            cs.newLineAtOffset(PAGE_WIDTH - MARGIN - 120, PAGE_HEIGHT - 49);
            cs.showText("Generated: " + date);
            cs.endText();

            y = PAGE_HEIGHT - 95;

            // ── Resumo ────────────────────────────────────────────────────────
            if (result != null) {
                String targetUrl = result.getFinalUrl() != null
                        ? result.getFinalUrl() : result.getUrl();

                cs.beginText();
                cs.setNonStrokingColor(new PDColor(
                        new float[]{0.35f, 0.48f, 0.59f}, PDDeviceRGB.INSTANCE));
                cs.setFont(fontBold, 9);
                cs.newLineAtOffset(MARGIN, y);
                cs.showText("TARGET: ");
                cs.endText();

                cs.beginText();
                cs.setNonStrokingColor(new PDColor(
                        new float[]{0f, 0.83f, 0.63f}, PDDeviceRGB.INSTANCE));
                cs.setFont(fontMono, 9);
                cs.newLineAtOffset(MARGIN + 50, y);
                cs.showText(sanitize(targetUrl));
                cs.endText();
                y -= LINE_HEIGHT;

                if (result.getScore() != null) {
                    int    score    = result.getScore().getScore();
                    String risk     = result.getScore().getRiskLevel() != null
                            ? result.getScore().getRiskLevel().name()
                            : "UNKNOWN";
                    float[] rcColor = riskToColor(risk);

                    cs.beginText();
                    cs.setNonStrokingColor(new PDColor(
                            new float[]{0.35f, 0.48f, 0.59f}, PDDeviceRGB.INSTANCE));
                    cs.setFont(fontBold, 9);
                    cs.newLineAtOffset(MARGIN, y);
                    cs.showText("SCORE:  ");
                    cs.endText();

                    cs.beginText();
                    cs.setNonStrokingColor(new PDColor(rcColor, PDDeviceRGB.INSTANCE));
                    cs.setFont(fontBold, 9);
                    cs.newLineAtOffset(MARGIN + 50, y);
                    cs.showText(score + "/100  [" + risk + "]");
                    cs.endText();
                    y -= LINE_HEIGHT;
                }

                y -= 5;
                cs.setStrokingColor(new PDColor(
                        new float[]{0.11f, 0.17f, 0.24f}, PDDeviceRGB.INSTANCE));
                cs.setLineWidth(0.5f);
                cs.moveTo(MARGIN, y);
                cs.lineTo(PAGE_WIDTH - MARGIN, y);
                cs.stroke();
                y -= 12;
            }

            // ── Conteúdo do relatório ─────────────────────────────────────────
            for (String rawLine : reportText.replace("\r\n", "\n").replace("\r", "\n").split("\n")) {
                String line = sanitize(rawLine);

                if (y < MARGIN + 20) {
                    cs.close();
                    page = new PDPage(PDRectangle.A4);
                    doc.addPage(page);
                    cs = new PDPageContentStream(doc, page);
                    y = PAGE_HEIGHT - MARGIN;
                }

                if (line.startsWith("===") || line.startsWith("---")) {
                    cs.setStrokingColor(new PDColor(
                            new float[]{0.11f, 0.17f, 0.24f}, PDDeviceRGB.INSTANCE));
                    cs.setLineWidth(0.3f);
                    cs.moveTo(MARGIN, y + 4);
                    cs.lineTo(PAGE_WIDTH - MARGIN, y + 4);
                    cs.stroke();
                } else if (line.startsWith("##") || line.startsWith("  ##")) {
                    cs.beginText();
                    cs.setNonStrokingColor(new PDColor(
                            new float[]{0f, 0.83f, 0.63f}, PDDeviceRGB.INSTANCE));
                    cs.setFont(fontBold, 10);
                    cs.newLineAtOffset(MARGIN, y);
                    cs.showText(truncate(line.replace("#", "").trim(), 95));
                    cs.endText();
                } else if (line.contains("CRITICAL") || line.contains("HIGH")) {
                    cs.beginText();
                    cs.setNonStrokingColor(new PDColor(
                            new float[]{1f, 0.25f, 0.25f}, PDDeviceRGB.INSTANCE));
                    cs.setFont(fontNormal, 9);
                    cs.newLineAtOffset(MARGIN, y);
                    cs.showText(truncate(line, 100));
                    cs.endText();
                } else if (line.contains("MEDIUM") || line.contains("WARNING")) {
                    cs.beginText();
                    cs.setNonStrokingColor(new PDColor(
                            new float[]{0.96f, 0.65f, 0.14f}, PDDeviceRGB.INSTANCE));
                    cs.setFont(fontNormal, 9);
                    cs.newLineAtOffset(MARGIN, y);
                    cs.showText(truncate(line, 100));
                    cs.endText();
                } else if (line.contains("OK") || line.contains("SECURE") || line.startsWith("  +")) {
                    cs.beginText();
                    cs.setNonStrokingColor(new PDColor(
                            new float[]{0f, 0.78f, 0.48f}, PDDeviceRGB.INSTANCE));
                    cs.setFont(fontNormal, 9);
                    cs.newLineAtOffset(MARGIN, y);
                    cs.showText(truncate(line, 100));
                    cs.endText();
                } else {
                    cs.beginText();
                    cs.setNonStrokingColor(new PDColor(
                            new float[]{0.72f, 0.80f, 0.87f}, PDDeviceRGB.INSTANCE));
                    cs.setFont(fontNormal, 9);
                    cs.newLineAtOffset(MARGIN, y);
                    cs.showText(truncate(line, 100));
                    cs.endText();
                }

                y -= LINE_HEIGHT;
            }

            // ── Rodapé ────────────────────────────────────────────────────────
            cs.beginText();
            cs.setNonStrokingColor(new PDColor(
                    new float[]{0.35f, 0.48f, 0.59f}, PDDeviceRGB.INSTANCE));
            cs.setFont(fontNormal, 8);
            cs.newLineAtOffset(MARGIN, 30);
            cs.showText("CyberAudit Security Scanner  |  Confidential Report");
            cs.endText();

            cs.close();
            doc.save(out);
            return out.toByteArray();

        } catch (Exception e) {
            throw new RuntimeException("Erro ao gerar PDF: " + e.getMessage(), e);
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private String sanitize(String text) {
        if (text == null) return "";
        text = text.replace("\r", "").replace("\t", "  "); // ← remove CR e tab
        return text
                .replace("\u00e3", "a").replace("\u00e2", "a").replace("\u00e1", "a").replace("\u00e0", "a")
                .replace("\u00ea", "e").replace("\u00e9", "e").replace("\u00e8", "e")
                .replace("\u00ed", "i").replace("\u00ee", "i")
                .replace("\u00f5", "o").replace("\u00f4", "o").replace("\u00f3", "o").replace("\u00f2", "o")
                .replace("\u00fa", "u").replace("\u00fb", "u").replace("\u00fc", "u")
                .replace("\u00e7", "c")
                .replace("\u00c3", "A").replace("\u00c2", "A").replace("\u00c1", "A").replace("\u00c0", "A")
                .replace("\u00ca", "E").replace("\u00c9", "E").replace("\u00c8", "E")
                .replace("\u00cd", "I").replace("\u00ce", "I")
                .replace("\u00d5", "O").replace("\u00d4", "O").replace("\u00d3", "O")
                .replace("\u00da", "U").replace("\u00db", "U").replace("\u00dc", "U")
                .replace("\u00c7", "C")
                .replace("\u2014", "--").replace("\u2013", "-")
                .replace("\u2019", "'").replace("\u2018", "'")
                .replace("\u201c", "\"").replace("\u201d", "\"")
                .replace("\u00b7", ".").replace("\u2022", "*")
                .replaceAll("[^\\x00-\\x7E]", "?");
    }

    private String truncate(String text, int maxLen) {
        if (text == null) return "";
        return text.length() <= maxLen ? text : text.substring(0, maxLen - 3) + "...";
    }

    private float[] riskToColor(String risk) {
        if (risk == null) return new float[]{0.72f, 0.80f, 0.87f};
        return switch (risk.toUpperCase()) {
            case "SECURE"   -> new float[]{0f, 0.78f, 0.48f};
            case "WARNING"  -> new float[]{0.96f, 0.65f, 0.14f};
            case "CRITICAL" -> new float[]{1f, 0.25f, 0.25f};
            default         -> new float[]{0.72f, 0.80f, 0.87f};
        };
    }
}