package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.ScanResult;
import org.apache.pdfbox.pdmodel.*;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.time.LocalDateTime;

@Service
public class PdfReportService {

    public byte[] generatePdf(ScanResult result, String reportText) {

        try (PDDocument doc = new PDDocument();
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {

            PDPage page = new PDPage();
            doc.addPage(page);

            PDPageContentStream cs = new PDPageContentStream(doc, page);

            float margin = 50;
            float y = page.getMediaBox().getHeight() - margin;

            // Título
            cs.beginText();
            cs.setFont(PDType1Font.HELVETICA_BOLD, 18);
            cs.newLineAtOffset(margin, y);
            cs.showText("WEB SECURITY REPORT");
            cs.endText();

            y -= 30;

            // Data
            cs.beginText();
            cs.setFont(PDType1Font.HELVETICA, 10);
            cs.newLineAtOffset(margin, y);
            cs.showText("Generated: " + LocalDateTime.now());
            cs.endText();

            y -= 25;

            // Conteúdo do relatório
            String[] lines = reportText.split("\n");

            cs.setFont(PDType1Font.HELVETICA, 10);

            for (String line : lines) {

                if (y < 50) {
                    cs.close();
                    page = new PDPage();
                    doc.addPage(page);
                    cs = new PDPageContentStream(doc, page);
                    y = page.getMediaBox().getHeight() - margin;
                    cs.setFont(PDType1Font.HELVETICA, 10);
                }

                cs.beginText();
                cs.newLineAtOffset(margin, y);
                cs.showText(line);
                cs.endText();

                y -= 14;
            }

            cs.close();
            doc.save(out);

            return out.toByteArray();

        } catch (Exception e) {
            throw new RuntimeException("Erro gerando PDF", e);
        }
    }
}