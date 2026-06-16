package com.joao.cyberaudit.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.joao.cyberaudit.model.*;
import com.joao.cyberaudit.repository.ScanRecordRepository;
import org.apache.pdfbox.pdmodel.*;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.*;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import java.io.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Gera um PDF executivo consolidado por conta:
 * capa com resumo geral → seção por domínio → tabela de issues críticos/altos.
 *
 * Thread-safety: synchronized no ponto de entrada (geração é rápida).
 */
@Service
public class ExecutivePdfReportService {

    // ── Layout ────────────────────────────────────────────────────────────────
    private static final float M  = 45f;
    private static final float LH = 13f;
    private static final float PH = PDRectangle.A4.getHeight();   // 841.89
    private static final float PW = PDRectangle.A4.getWidth();    // 595.28
    private static final float CW = PW - 2 * M;                  // ~505

    // ── Cores (R G B, 0-1) ───────────────────────────────────────────────────
    private static final float[] NAVY    = {0.05f, 0.08f, 0.12f};
    private static final float[] ACCENT  = {0f,    0.83f, 0.63f};
    private static final float[] WHITE   = {1f,    1f,    1f};
    private static final float[] TEXT    = {0.12f, 0.16f, 0.22f};
    private static final float[] MUTED   = {0.42f, 0.50f, 0.58f};
    private static final float[] BORDER  = {0.86f, 0.89f, 0.92f};
    private static final float[] BGLIGHT = {0.96f, 0.97f, 0.98f};
    private static final float[] BGDARK  = {0.09f, 0.13f, 0.19f};
    private static final float[] CRIT    = {0.84f, 0.10f, 0.10f};
    private static final float[] HIGH_C  = {0.89f, 0.40f, 0.05f};
    private static final float[] MED_C   = {0.76f, 0.52f, 0.04f};
    private static final float[] LOW_C   = {0.18f, 0.44f, 0.76f};
    private static final float[] OK      = {0.05f, 0.60f, 0.36f};

    private static final DateTimeFormatter DT_FMT =
            DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm");
    private static final DateTimeFormatter D_FMT =
            DateTimeFormatter.ofPattern("dd/MM/yyyy");

    // ── Estado por chamada (synchronized) ────────────────────────────────────
    private PDDocument           doc;
    private PDPageContentStream  cs;
    private float                cy;
    private int                  pageNo;
    private PDType1Font          bold, normal, mono;

    // ── Dependências ──────────────────────────────────────────────────────────
    private final ScanRecordRepository scanRecordRepository;
    private final ObjectMapper         objectMapper;

    public ExecutivePdfReportService(ScanRecordRepository scanRecordRepository,
                                     ObjectMapper objectMapper) {
        this.scanRecordRepository = scanRecordRepository;
        this.objectMapper         = objectMapper;
    }

    // ── Entry point ───────────────────────────────────────────────────────────

    public synchronized byte[] generate(Account account, List<Domain> domains) {
        try {
            doc    = new PDDocument();
            bold   = PDType1Font.HELVETICA_BOLD;
            normal = PDType1Font.HELVETICA;
            mono   = PDType1Font.COURIER;
            pageNo = 0;
            cs     = null;

            // Coleta último scan por domínio
            List<DomainReport> reports = domains.stream()
                    .map(this::buildDomainReport)
                    .collect(Collectors.toList());

            // Capa
            openPage();
            coverPage(account, reports);
            closePage();

            // Seção por domínio
            if (!reports.isEmpty()) {
                openPage();
                for (DomainReport dr : reports) {
                    domainBlock(dr);
                }
                closePage();
            }

            // Tabela consolidada de issues críticos/altos
            List<IssueRow> critical = collectCritical(reports);
            if (!critical.isEmpty()) {
                openPage();
                criticalTable(critical);
                closePage();
            }

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            doc.save(out);
            doc.close();
            return out.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException("Erro ao gerar PDF executivo: " + e.getMessage(), e);
        }
    }

    // ── Coleta de dados ───────────────────────────────────────────────────────

    private DomainReport buildDomainReport(Domain domain) {
        List<ScanRecord> records = scanRecordRepository
                .findByHostOrderByScannedAtDesc(domain.getHost(), PageRequest.of(0, 5));

        if (records.isEmpty()) {
            return new DomainReport(domain, null, null, null);
        }

        ScanRecord latest   = records.get(0);
        ScanRecord previous = records.size() > 1 ? records.get(1) : null;
        ScanResult result   = deserialize(latest);
        return new DomainReport(domain, latest, result, previous);
    }

    private ScanResult deserialize(ScanRecord record) {
        try {
            return objectMapper.readValue(record.getResultJson(), ScanResult.class);
        } catch (Exception e) {
            return null;
        }
    }

    private List<IssueRow> collectCritical(List<DomainReport> reports) {
        List<IssueRow> rows = new ArrayList<>();
        for (DomainReport dr : reports) {
            if (dr.result() == null || dr.result().getScore() == null
                    || dr.result().getScore().getIssues() == null) continue;
            for (SecurityIssue issue : dr.result().getScore().getIssues()) {
                if ("CRITICAL".equals(issue.getSeverity()) || "HIGH".equals(issue.getSeverity())) {
                    rows.add(new IssueRow(dr.domain().getHost(), issue));
                }
            }
        }
        rows.sort(Comparator.comparing(r -> severityOrder(r.issue().getSeverity())));
        return rows;
    }

    private int severityOrder(String s) {
        return switch (s == null ? "" : s) {
            case "CRITICAL" -> 0;
            case "HIGH"     -> 1;
            case "MEDIUM"   -> 2;
            default         -> 3;
        };
    }

    // ── Capa ─────────────────────────────────────────────────────────────────

    private void coverPage(Account account, List<DomainReport> reports) throws IOException {
        // Header bar
        fill(0, PH - 110, PW, 110, NAVY);
        fill(0, PH - 110, 5, 110, ACCENT);
        txt("CYBERAUDIT", M + 10, PH - 38, bold, 24, ACCENT);
        txt("Relatório Executivo de Segurança", M + 10, PH - 60, normal, 12, WHITE);
        String now = java.time.LocalDateTime.now().format(DT_FMT);
        txtR("Gerado em " + now, PW - M, PH - 42, normal, 9, MUTED);
        txtR("CONFIDENCIAL", PW - M, PH - 58, bold, 8, MUTED);
        cy = PH - 130;

        // Account info box
        gap(12);
        fill(M, cy - 52, CW, 52, BGLIGHT);
        strokeRect(M, cy - 52, CW, 52, BORDER);
        fill(M, cy - 52, 4, 52, ACCENT);
        txt(account.getDisplayName(), M + 16, cy - 18, bold, 14, TEXT);
        txt("Conta " + account.getType().name() +
            (account.getPlan() != null ? " · Plano " + account.getPlan().name() : ""),
            M + 16, cy - 34, normal, 9, MUTED);
        if (account.getCompanyName() != null) {
            txt(account.getCompanyName(), M + 16, cy - 46, normal, 9, MUTED);
        }
        cy -= 62;

        // Stats row
        gap(16);
        long totalDomains    = reports.size();
        long verifiedDomains = reports.stream().filter(dr -> dr.domain().isVerified()).count();
        long scannedDomains  = reports.stream().filter(dr -> dr.latest() != null).count();

        OptionalDouble avgScore = reports.stream()
                .filter(dr -> dr.latest() != null)
                .mapToInt(dr -> dr.latest().getScore())
                .average();

        long criticalCount = reports.stream()
                .filter(dr -> dr.result() != null && dr.result().getScore() != null
                        && dr.result().getScore().getIssues() != null)
                .flatMap(dr -> dr.result().getScore().getIssues().stream())
                .filter(i -> "CRITICAL".equals(i.getSeverity()))
                .count();

        float boxW = (CW - 9) / 4f;
        statBox(M,              cy, boxW, 72, String.valueOf(totalDomains),    "Domínios", null);
        statBox(M + boxW + 3,   cy, boxW, 72, String.valueOf(verifiedDomains), "Verificados", ACCENT);
        statBox(M + 2*(boxW+3), cy, boxW, 72,
                avgScore.isPresent() ? String.valueOf((int)avgScore.getAsDouble()) : "—",
                "Score Médio", scoreColor(avgScore.isPresent() ? (int)avgScore.getAsDouble() : -1));
        statBox(M + 3*(boxW+3), cy, boxW, 72, String.valueOf(criticalCount), "Issues Críticos",
                criticalCount > 0 ? CRIT : OK);
        cy -= 82;

        // Risk summary by domain
        gap(20);
        sectionTitle("RESUMO POR RISCO");
        gap(6);

        Map<String, Long> byRisk = reports.stream()
                .filter(dr -> dr.latest() != null && dr.latest().getRiskLevel() != null)
                .collect(Collectors.groupingBy(
                        dr -> dr.latest().getRiskLevel().name(), Collectors.counting()));

        float barY = cy;
        float barTotalW = CW;
        long total = reports.stream().filter(dr -> dr.latest() != null).count();

        // Risk distribution bar
        if (total > 0) {
            float[] riskColors = CRIT;
            float xOff = M;
            for (String[] entry : new String[][]{
                    {"CRITICAL", "Crítico"}, {"HIGH", "Alto"},
                    {"MEDIUM", "Médio"}, {"LOW", "Baixo"}, {"MINIMAL", "Mínimo"}}) {
                long count = byRisk.getOrDefault(entry[0], 0L);
                if (count == 0) continue;
                float segW = barTotalW * count / total;
                float[] col = riskColor(entry[0]);
                fill(xOff, barY - 20, segW, 20, col);
                if (segW > 40) {
                    txt(entry[1] + " (" + count + ")", xOff + 4, barY - 7, normal, 8, WHITE);
                }
                xOff += segW;
            }
            cy -= 28;
        }

        if (scannedDomains == 0) {
            gap(20);
            txt("Nenhum domínio foi escaneado ainda. Execute scans nos domínios registrados para gerar dados.",
                M, cy, normal, 10, MUTED);
            cy -= 14;
        }
    }

    // ── Bloco por domínio ─────────────────────────────────────────────────────

    private void domainBlock(DomainReport dr) throws IOException {
        float blockH = dr.result() != null ? estimateDomainBlockH(dr) : 60;
        need(blockH + 20);

        gap(14);
        float startY = cy;

        // Header do domínio
        fill(M, cy - 32, CW, 32, BGDARK);
        fill(M, cy - 32, 4, 32, domainAccentColor(dr));
        txt(dr.domain().getHost(), M + 12, cy - 12, bold, 12, WHITE);

        String verBadge = dr.domain().isVerified() ? "✓ VERIFICADO" : "NÃO VERIFICADO";
        float[] verColor = dr.domain().isVerified() ? ACCENT : MUTED;
        txt(verBadge, M + 12, cy - 26, bold, 8, verColor);

        if (dr.latest() != null) {
            // Score grande
            String scoreStr = String.valueOf(dr.latest().getScore());
            float[] scoreCol = scoreColor(dr.latest().getScore());
            txtR(scoreStr, PW - M - 60, cy - 8, bold, 22, scoreCol);
            txtR("/ 100", PW - M - 8, cy - 8, normal, 10, MUTED);

            String risk = dr.latest().getRiskLevel() != null
                    ? dr.latest().getRiskLevel().name() : "—";
            txtR(risk, PW - M - 8, cy - 24, bold, 9, riskColor(risk));

            cy -= 38;

            // Meta do scan
            txt("Último scan: " + dr.latest().getScannedAt().format(DT_FMT) +
                (dr.latest().isActiveMode() ? " (ativo)" : " (passivo)"),
                M + 12, cy - 2, normal, 8, MUTED);

            // Trend
            if (dr.previous() != null) {
                int delta = dr.latest().getScore() - dr.previous().getScore();
                String trend = delta > 0 ? "▲ +" + delta : delta < 0 ? "▼ " + delta : "→ sem mudança";
                float[] trendCol = delta > 0 ? OK : delta < 0 ? CRIT : MUTED;
                txtR(trend, PW - M - 8, cy - 2, bold, 8, trendCol);
            }
            cy -= 12;

            // Issues do domínio
            if (dr.result() != null && dr.result().getScore() != null
                    && dr.result().getScore().getIssues() != null) {
                List<SecurityIssue> issues = dr.result().getScore().getIssues().stream()
                        .sorted(Comparator.comparing(i -> severityOrder(i.getSeverity())))
                        .limit(5)
                        .toList();

                if (!issues.isEmpty()) {
                    gap(6);
                    for (SecurityIssue issue : issues) {
                        need(18);
                        float[] col = severityColor(issue.getSeverity());
                        fill(M + 12, cy - 14, 55, 14, col);
                        txt(issue.getSeverity(), M + 14, cy - 4, bold, 7, WHITE);
                        String title = truncate(issue.getTitle(), 70);
                        txt(title, M + 74, cy - 4, normal, 9, TEXT);
                        cy -= 16;
                    }
                }
            }
        } else {
            cy -= 38;
            txt("Nenhum scan realizado para este domínio.", M + 12, cy - 8, normal, 9, MUTED);
            cy -= 18;
        }

        // Separador
        gap(6);
        fill(M, cy, CW, 0.5f, BORDER);
    }

    // ── Tabela de issues críticos/altos ───────────────────────────────────────

    private void criticalTable(List<IssueRow> rows) throws IOException {
        sectionTitle("FINDINGS CRÍTICOS E ALTOS — CONSOLIDADO");
        gap(10);

        // Cabeçalho da tabela
        float[] cols = {M, M + 140, M + 280, M + 360};
        float rowH = 18;
        fill(M, cy - rowH, CW, rowH, BGDARK);
        txt("Domínio",    cols[0] + 4, cy - 6, bold, 8, MUTED);
        txt("Issue",      cols[1] + 4, cy - 6, bold, 8, MUTED);
        txt("Severidade", cols[2] + 4, cy - 6, bold, 8, MUTED);
        txt("Impacto",    cols[3] + 4, cy - 6, bold, 8, MUTED);
        cy -= rowH;

        boolean alt = false;
        for (IssueRow row : rows) {
            need(rowH + 2);
            if (alt) fill(M, cy - rowH, CW, rowH, BGLIGHT);
            txt(truncate(row.host(), 22),           cols[0] + 4, cy - 6, mono,   7, TEXT);
            txt(truncate(row.issue().getTitle(), 22),  cols[1] + 4, cy - 6, normal, 8, TEXT);
            fill(cols[2] + 4, cy - 14, 62, 12, severityColor(row.issue().getSeverity()));
            txt(row.issue().getSeverity(), cols[2] + 6, cy - 5, bold, 7, WHITE);
            txt(truncate(row.issue().getImpact(), 26), cols[3] + 4, cy - 6, normal, 7, MUTED);
            fill(M, cy - rowH, CW, 0.3f, BORDER);
            cy -= rowH;
            alt = !alt;
        }
    }

    // ── Helpers de layout ─────────────────────────────────────────────────────

    private void statBox(float x, float y, float w, float h,
                         String value, String label, float[] valueColor) throws IOException {
        fill(x, y - h, w, h, BGLIGHT);
        strokeRect(x, y - h, w, h, BORDER);
        float[] col = valueColor != null ? valueColor : TEXT;
        txt(value, x + w / 2f - textWidth(value, bold, 26) / 2f,
            y - h / 2f + 8, bold, 26, col);
        txt(label, x + w / 2f - textWidth(label, normal, 8) / 2f,
            y - h + 12, normal, 8, MUTED);
    }

    private void sectionTitle(String title) throws IOException {
        need(28);
        fill(M, cy - 20, CW, 20, BGDARK);
        fill(M, cy - 20, 3, 20, ACCENT);
        txt(title, M + 10, cy - 7, bold, 9, ACCENT);
        cy -= 22;
    }

    private float estimateDomainBlockH(DomainReport dr) {
        int issues = 0;
        if (dr.result() != null && dr.result().getScore() != null
                && dr.result().getScore().getIssues() != null) {
            issues = Math.min(5, dr.result().getScore().getIssues().size());
        }
        return 70 + issues * 17f;
    }

    private float[] domainAccentColor(DomainReport dr) {
        if (dr.latest() == null) return MUTED;
        if (dr.latest().getRiskLevel() == null) return MUTED;
        return riskColor(dr.latest().getRiskLevel().name());
    }

    private void gap(float h) { cy -= h; }

    private float textWidth(String text, PDType1Font font, float size) {
        try { return font.getStringWidth(text) / 1000f * size; }
        catch (Exception e) { return text.length() * size * 0.5f; }
    }

    private String truncate(String s, int max) {
        if (s == null) return "—";
        return s.length() <= max ? s : s.substring(0, max - 1) + "…";
    }

    // ── Page management ───────────────────────────────────────────────────────

    private void openPage() throws IOException {
        PDPage page = new PDPage(PDRectangle.A4);
        doc.addPage(page);
        cs = new PDPageContentStream(doc, page);
        pageNo++;
        cy = PH - M;
    }

    private void closePage() throws IOException {
        fill(M, 28, CW, 0.5f, BORDER);
        txt("CyberAudit · Relatório Executivo  —  Confidencial", M, 18, normal, 7, MUTED);
        txtR("Página " + pageNo, PW - M, 18, normal, 7, MUTED);
        cs.close();
    }

    private void need(float h) throws IOException {
        if (cy - h < 55) {
            closePage();
            openPage();
        }
    }

    // ── Drawing primitives ────────────────────────────────────────────────────

    private void fill(float x, float y, float w, float h, float[] rgb) throws IOException {
        cs.setNonStrokingColor(rgb[0], rgb[1], rgb[2]);
        cs.addRect(x, y, w, h);
        cs.fill();
    }

    private void strokeRect(float x, float y, float w, float h, float[] rgb) throws IOException {
        cs.setStrokingColor(rgb[0], rgb[1], rgb[2]);
        cs.setLineWidth(0.5f);
        cs.addRect(x, y, w, h);
        cs.stroke();
    }

    private void txt(String text, float x, float y, PDType1Font font,
                     float size, float[] rgb) throws IOException {
        if (text == null || text.isBlank()) return;
        cs.beginText();
        cs.setNonStrokingColor(rgb[0], rgb[1], rgb[2]);
        cs.setFont(font, size);
        cs.newLineAtOffset(x, y);
        cs.showText(sanitize(text));
        cs.endText();
    }

    private void txtR(String text, float rightX, float y,
                      PDType1Font font, float size, float[] rgb) throws IOException {
        if (text == null || text.isBlank()) return;
        float w = textWidth(text, font, size);
        txt(text, rightX - w, y, font, size, rgb);
    }

    private String sanitize(String s) {
        if (s == null) return "";
        return s.chars()
                .filter(c -> c >= 32 && c < 127)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();
    }

    // ── Cor helpers ───────────────────────────────────────────────────────────

    private float[] scoreColor(int score) {
        if (score < 0)  return MUTED;
        if (score < 40) return CRIT;
        if (score < 60) return HIGH_C;
        if (score < 75) return MED_C;
        if (score < 90) return LOW_C;
        return OK;
    }

    private float[] riskColor(String risk) {
        return switch (risk == null ? "" : risk) {
            case "CRITICAL" -> CRIT;
            case "HIGH"     -> HIGH_C;
            case "MEDIUM"   -> MED_C;
            case "LOW"      -> LOW_C;
            default         -> OK;
        };
    }

    private float[] severityColor(String sev) {
        return switch (sev == null ? "" : sev) {
            case "CRITICAL" -> CRIT;
            case "HIGH"     -> HIGH_C;
            case "MEDIUM"   -> MED_C;
            case "LOW"      -> LOW_C;
            default         -> MUTED;
        };
    }

    // ── Records internos ──────────────────────────────────────────────────────

    private record DomainReport(
            Domain     domain,
            ScanRecord latest,
            ScanResult result,
            ScanRecord previous
    ) {}

    private record IssueRow(String host, SecurityIssue issue) {}
}
