package com.joao.cyberaudit.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.joao.cyberaudit.model.*;
import com.joao.cyberaudit.repository.AuditLogRepository;
import com.joao.cyberaudit.repository.ScanRecordRepository;
import org.apache.pdfbox.pdmodel.*;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.*;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import java.io.*;
import java.net.URI;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Escopo do relatório executivo:
 * DOMAINS   → apenas domínios cadastrados na conta
 * TEAM_SCANS → apenas scans realizados pela equipe (vinculados à conta, sem domínio registrado)
 * BOTH       → domínios cadastrados + scans adicionais da equipe
 */

/**
 * Gera um PDF executivo consolidado por conta:
 * capa com resumo geral → seção por domínio → tabela de issues críticos/altos.
 *
 * Thread-safety: synchronized no ponto de entrada (geração é rápida).
 *
 * DOCUMENTO EM INGLÊS, POR DECISÃO — não passa pelo MessageCatalog.
 *
 * A interface é bilíngue (ver LocaleConfig); os relatórios exportáveis, não. É o
 * arquivo que o cliente encaminha para auditor, área de compliance ou cliente
 * dele, e inglês é a língua franca de laudo técnico de segurança. Um PDF que muda
 * de idioma conforme quem clicou "exportar" atrapalha justamente esse uso.
 *
 * Consequência conhecida: o TEXTO DOS ACHADOS dentro do documento vem do
 * ScanResult, que é montado no idioma da requisição. Um cliente navegando em
 * português exporta PDF com moldura em inglês e achados em português — como
 * sempre foi. Deixar tudo em inglês exigiria o resultado guardar ID + parâmetros
 * em vez de texto pronto, que é mudança de contrato registrada no PLANO_EXECUCAO.
 *
 * Ao adicionar texto aqui: escreva em inglês.
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
    private final AuditLogRepository   auditLogRepository;
    private final ObjectMapper         objectMapper;

    public ExecutivePdfReportService(ScanRecordRepository scanRecordRepository,
                                     AuditLogRepository auditLogRepository,
                                     ObjectMapper objectMapper) {
        this.scanRecordRepository = scanRecordRepository;
        this.auditLogRepository   = auditLogRepository;
        this.objectMapper         = objectMapper;
    }

    // ── Entry point ───────────────────────────────────────────────────────────

    /**
     * Gera o PDF com escopo e filtro de datas.
     *
     * @param scope    DOMAINS = apenas domínios cadastrados; TEAM_SCANS = todos os scans da conta;
     *                 BOTH = domínios cadastrados + scans extras da equipe
     * @param from     data inicial (null = sem limite)
     * @param to       data final   (null = sem limite)
     */
    public synchronized byte[] generate(Account account, List<Domain> domains,
                                        ReportScope scope, LocalDate from, LocalDate to) {
        LocalDateTime dtFrom = from != null ? from.atStartOfDay()             : LocalDateTime.MIN;
        LocalDateTime dtTo   = to   != null ? to.atTime(23, 59, 59)           : LocalDateTime.MAX;
        boolean hasDateFilter = from != null || to != null;

        try {
            doc    = new PDDocument();
            bold   = PDType1Font.HELVETICA_BOLD;
            normal = PDType1Font.HELVETICA;
            mono   = PDType1Font.COURIER;
            pageNo = 0;
            cs     = null;

            List<DomainReport> reports;
            if (scope == ReportScope.TEAM_SCANS) {
                // Todos os scans da conta: account-linked (novos) + AuditLog (histórico)
                reports = buildReportsFromAccountScans(account, dtFrom, dtTo);
            } else if (scope == ReportScope.BOTH) {
                // Domínios cadastrados + quaisquer scans extras da equipe
                List<DomainReport> domainReports = domains.stream()
                        .map(d -> buildDomainReport(d, dtFrom, dtTo))
                        .collect(Collectors.toList());
                Set<String> coveredHosts = domainReports.stream()
                        .map(DomainReport::host).collect(Collectors.toSet());
                List<DomainReport> teamReports = buildReportsFromAccountScans(account, dtFrom, dtTo)
                        .stream()
                        .filter(dr -> !coveredHosts.contains(dr.host()))
                        .collect(Collectors.toList());
                reports = new ArrayList<>(domainReports);
                reports.addAll(teamReports);
            } else { // DOMAINS: apenas domínios cadastrados (sem fallback)
                reports = domains.stream()
                        .map(d -> buildDomainReport(d, dtFrom, dtTo))
                        .collect(Collectors.toList());
            }

            // Capa + tabela na mesma página (need() abre nova página se necessário)
            openPage();
            coverPage(account, reports, scope, from, to);
            if (!reports.isEmpty()) {
                domainTable(reports, scope);
            }
            closePage();

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            doc.save(out);
            doc.close();
            return out.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate executive PDF: " + e.getMessage(), e);
        }
    }

    // ── Coleta de dados ───────────────────────────────────────────────────────

    private DomainReport buildDomainReport(Domain domain, LocalDateTime from, LocalDateTime to) {
        String host = domain.getHost();
        boolean hasFilter = !from.equals(LocalDateTime.MIN) || !to.equals(LocalDateTime.MAX);

        List<ScanRecord> records = hasFilter
                ? scanRecordRepository.findByHostAndScannedAtBetweenOrderByScannedAtDesc(
                        host, from, to, PageRequest.of(0, 5))
                : scanRecordRepository.findByHostOrderByScannedAtDesc(host, PageRequest.of(0, 5));

        // Fallback: tenta com/sem "www." para cobrir registros gravados antes da normalização
        if (records.isEmpty()) {
            String alt = host.startsWith("www.") ? host.substring(4) : "www." + host;
            records = hasFilter
                    ? scanRecordRepository.findByHostAndScannedAtBetweenOrderByScannedAtDesc(
                            alt, from, to, PageRequest.of(0, 5))
                    : scanRecordRepository.findByHostOrderByScannedAtDesc(alt, PageRequest.of(0, 5));
        }

        if (records.isEmpty()) {
            return new DomainReport(host, domain.isVerified(), null, null, null);
        }

        ScanRecord latest   = records.get(0);
        ScanRecord previous = records.size() > 1 ? records.get(1) : null;
        ScanResult result   = deserialize(latest);
        return new DomainReport(host, domain.isVerified(), latest, result, previous);
    }

    /**
     * Scans da equipe vinculados à conta (um por host distinto),
     * opcionalmente filtrados por intervalo de datas.
     *
     * Estratégia em duas etapas:
     * 1) Tenta via account_id (scans novos, pós-migração).
     * 2) Se vazio, usa AuditLog SCAN_COMPLETED para descobrir os hosts
     *    e busca ScanRecord por host (cobre dados pré-migração sem account_id).
     */
    private List<DomainReport> buildReportsFromAccountScans(Account account,
                                                            LocalDateTime from, LocalDateTime to) {
        if (account == null) return List.of();
        boolean hasFilter = !from.equals(LocalDateTime.MIN) || !to.equals(LocalDateTime.MAX);

        // Fonte 1: ScanRecord com account_id preenchido (scans pós-migração)
        List<ScanRecord> fromAccount = hasFilter
                ? scanRecordRepository.findLatestPerHostByAccountBetween(
                        account, from, to, PageRequest.of(0, 50))
                : scanRecordRepository.findLatestPerHostByAccount(account, PageRequest.of(0, 50));

        // Fonte 2: AuditLog (dados históricos sem account_id — pré-migração)
        // Sempre mescla para não perder scans anteriores à adição do FK
        Set<String> coveredHosts = fromAccount.stream()
                .map(ScanRecord::getHost).collect(Collectors.toSet());
        List<ScanRecord> fromAuditLog = account.getId() != null
                ? buildFromAuditLog(account, from, to).stream()
                        .filter(r -> !coveredHosts.contains(r.getHost()))
                        .collect(Collectors.toList())
                : List.of();

        List<ScanRecord> latestPerHost = new ArrayList<>(fromAccount);
        latestPerHost.addAll(fromAuditLog);

        return latestPerHost.stream().map(record -> {
            List<ScanRecord> history = hasFilter
                    ? scanRecordRepository.findByHostAndScannedAtBetweenOrderByScannedAtDesc(
                            record.getHost(), from, to, PageRequest.of(0, 2))
                    : scanRecordRepository.findByHostOrderByScannedAtDesc(
                            record.getHost(), PageRequest.of(0, 2));
            ScanRecord previous = history.size() > 1 ? history.get(1) : null;
            ScanResult result   = deserialize(record);
            return new DomainReport(record.getHost(), false, record, result, previous);
        }).collect(Collectors.toList());
    }

    /**
     * Fallback para dados pré-migração: descobre hosts via AuditLog
     * (SCAN_COMPLETED tem details = "{mode} — {url} — score={n}"),
     * extrai o host de cada URL distinta e busca o scan mais recente.
     */
    // Datas seguras para SQL TIMESTAMP (evita overflow com LocalDateTime.MIN / .MAX)
    private static final LocalDateTime SQL_FROM = LocalDateTime.of(2000, 1, 1, 0, 0);

    private List<ScanRecord> buildFromAuditLog(Account account,
                                               LocalDateTime from, LocalDateTime to) {
        // LocalDateTime.MIN/MAX causam overflow no JDBC. Usa limites seguros.
        LocalDateTime safeFrom = from.isBefore(SQL_FROM) ? SQL_FROM : from;
        LocalDateTime safeTo   = to.isAfter(LocalDateTime.now().plusDays(1))
                                 ? LocalDateTime.now().plusDays(1) : to;

        List<AuditLog> auditEntries = auditLogRepository
                .findScanCompletedByAccountBetween(
                        account.getId(), AuditAction.SCAN_COMPLETED, safeFrom, safeTo);

        // Extrai um ScanRecord por host distinto (o mais recente)
        Map<String, ScanRecord> byHost = new LinkedHashMap<>();
        for (AuditLog entry : auditEntries) {
            String url = extractUrlFromDetails(entry.getDetails());
            if (url == null) continue;
            String host = extractHostFromUrl(url);
            if (host == null || byHost.containsKey(host)) continue;
            List<ScanRecord> recs = scanRecordRepository
                    .findByHostOrderByScannedAtDesc(host, PageRequest.of(0, 1));
            if (!recs.isEmpty()) {
                byHost.put(host, recs.get(0));
            }
        }
        return new ArrayList<>(byHost.values());
    }

    /**
     * AuditLog.details para SCAN_COMPLETED: "passive — https://canva.com — score=75"
     * Extrai a URL (segundo segmento separado por " — ").
     */
    private String extractUrlFromDetails(String details) {
        if (details == null) return null;
        String[] parts = details.split("\\s*—\\s*");
        return parts.length >= 2 ? parts[1].trim() : null;
    }

    private String extractHostFromUrl(String url) {
        try {
            String h = URI.create(url).getHost();
            if (h == null) return null;
            return h.startsWith("www.") ? h.substring(4) : h;
        } catch (Exception e) {
            return null;
        }
    }

    private ScanResult deserialize(ScanRecord record) {
        try {
            return objectMapper.readValue(record.getResultJson(), ScanResult.class);
        } catch (Exception e) {
            return null;
        }
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

    private void coverPage(Account account, List<DomainReport> reports,
                           ReportScope scope, LocalDate from, LocalDate to) throws IOException {
        // ── Header bar (compact: 80px) ────────────────────────────────────────
        fill(0, PH - 80, PW, 80, NAVY);
        fill(0, PH - 80, 5, 80, ACCENT);
        txt("CYBERAUDIT", M + 10, PH - 24, bold, 22, ACCENT);
        txt("Executive Security Report", M + 10, PH - 44, normal, 11, WHITE);
        String now = java.time.LocalDateTime.now().format(DT_FMT);
        txtR("Generated on " + now, PW - M, PH - 28, normal, 8, MUTED);
        txtR("CONFIDENTIAL", PW - M, PH - 42, bold, 8, MUTED);
        String scopeLabel = switch (scope) {
            case TEAM_SCANS -> "Team Scans";
            case BOTH       -> "Domains + Team";
            default         -> "Registered Domains";
        };
        txtR(scopeLabel, PW - M, PH - 56, bold, 8, ACCENT);

        // Período do filtro
        String periodoStr;
        if (from != null && to != null) {
            periodoStr = "Period: " + from.format(DateTimeFormatter.ofPattern("dd/MM/yyyy"))
                       + " a " + to.format(DateTimeFormatter.ofPattern("dd/MM/yyyy"));
        } else if (from != null) {
            periodoStr = "Period: from " + from.format(DateTimeFormatter.ofPattern("dd/MM/yyyy"));
        } else if (to != null) {
            periodoStr = "Period: until " + to.format(DateTimeFormatter.ofPattern("dd/MM/yyyy"));
        } else {
            periodoStr = "Period: all records";
        }
        txtR(periodoStr, PW - M, PH - 68, normal, 8, MUTED);

        cy = PH - 92;

        // ── Account info box (compact: 38px) ─────────────────────────────────
        gap(6);
        fill(M, cy - 38, CW, 38, BGLIGHT);
        strokeRect(M, cy - 38, CW, 38, BORDER);
        fill(M, cy - 38, 4, 38, ACCENT);
        txt(account.getDisplayName(), M + 14, cy - 12, bold, 12, TEXT);
        String accountMeta = "Account " + account.getType().name()
                + (account.getPlan() != null ? "  ·  Plan " + account.getPlan().name() : "")
                + (account.getCompanyName() != null ? "  ·  " + account.getCompanyName() : "");
        txt(accountMeta, M + 14, cy - 28, normal, 8, MUTED);
        cy -= 44;

        // ── Stats row (compact: 54px) ─────────────────────────────────────────
        gap(8);
        long totalDomains   = reports.size();
        long scannedDomains = reports.stream().filter(dr -> dr.latest() != null).count();
        OptionalDouble avgScore = reports.stream()
                .filter(dr -> dr.latest() != null)
                .mapToInt(dr -> dr.latest().getScore())
                .average();
        long criticalCount = reports.stream()
                .filter(dr -> dr.result() != null && dr.result().getScore() != null
                        && dr.result().getScore().getIssues() != null)
                .flatMap(dr -> dr.result().getScore().getIssues().stream())
                .filter(i -> "CRITICAL".equals(i.getSeverity())).count();
        long highCount = reports.stream()
                .filter(dr -> dr.result() != null && dr.result().getScore() != null
                        && dr.result().getScore().getIssues() != null)
                .flatMap(dr -> dr.result().getScore().getIssues().stream())
                .filter(i -> "HIGH".equals(i.getSeverity())).count();

        float boxW = (CW - 9) / 4f;
        statBox(M,              cy, boxW, 54, String.valueOf(totalDomains),    "Targets", null);
        statBox(M + boxW + 3,   cy, boxW, 54, String.valueOf(scannedDomains), "Scanned", ACCENT);
        statBox(M + 2*(boxW+3), cy, boxW, 54,
                avgScore.isPresent() ? String.valueOf((int)avgScore.getAsDouble()) : "-",
                "Average Score",
                scoreColor(avgScore.isPresent() ? (int)avgScore.getAsDouble() : -1));
        statBox(M + 3*(boxW+3), cy, boxW, 54,
                criticalCount + " / " + highCount, "Critical / High",
                criticalCount > 0 ? CRIT : highCount > 0 ? HIGH_C : OK);
        cy -= 60;

        if (scannedDomains == 0) {
            gap(8);
            String noDataMsg = scope == ReportScope.DOMAINS
                    ? "No domain registered, or none scanned yet."
                    : "No scan found for this account in the selected period.";
            txt(noDataMsg, M, cy, normal, 9, MUTED);
            cy -= 14;
        }

        gap(10); // separação antes da tabela
    }

    // ── Tabela de listagem (substitui blocos por domínio) ─────────────────────

    private void domainTable(List<DomainReport> reports, ReportScope scope) throws IOException {
        boolean showVerified = (scope == ReportScope.DOMAINS || scope == ReportScope.BOTH);

        // Larguras das colunas
        float cHost   = showVerified ? 145f : 165f;
        float cScore  = 48f;
        float cRisk   = 80f;
        float cDate   = 112f;
        float cMode   = 58f;
        float cVer    = showVerified ? 62f : 0f;
        // total ≈ 145+48+80+112+58+62 = 505 = CW ✓

        float[] xCols = {
            M,
            M + cHost,
            M + cHost + cScore,
            M + cHost + cScore + cRisk,
            M + cHost + cScore + cRisk + cDate,
            M + cHost + cScore + cRisk + cDate + cMode,
        };

        String titleLabel = switch (scope) {
            case TEAM_SCANS -> "TEAM SCANS";
            case BOTH       -> "REGISTERED DOMAINS + TEAM SCANS";
            default         -> "REGISTERED DOMAINS";
        };
        sectionTitle(titleLabel);
        gap(8);

        float rowH = 20f;

        // Cabeçalho
        fill(M, cy - rowH, CW, rowH, BGDARK);
        txt("HOST",         xCols[0] + 4, cy - 7, bold, 8, MUTED);
        txt("SCORE",        xCols[1] + 4, cy - 7, bold, 8, MUTED);
        txt("RISK",        xCols[2] + 4, cy - 7, bold, 8, MUTED);
        txt("LAST SCAN",  xCols[3] + 4, cy - 7, bold, 8, MUTED);
        txt("MODE",         xCols[4] + 4, cy - 7, bold, 8, MUTED);
        if (showVerified) txt("STATUS", xCols[5] + 4, cy - 7, bold, 8, MUTED);
        cy -= rowH;

        boolean alt = false;
        for (DomainReport dr : reports) {
            need(rowH + 2);

            if (alt) fill(M, cy - rowH, CW, rowH, BGLIGHT);

            // HOST
            txt(truncate(dr.host(), showVerified ? 22 : 26),
                xCols[0] + 4, cy - 7, mono, 9, TEXT);

            if (dr.latest() != null) {
                // SCORE
                float[] scoreCol = scoreColor(dr.latest().getScore());
                String scoreStr  = String.valueOf(dr.latest().getScore());
                fill(xCols[1] + 2, cy - rowH + 3, cScore - 6, rowH - 6, scoreCol);
                txt(scoreStr,
                    xCols[1] + 2 + (cScore - 6) / 2f - textWidth(scoreStr, bold, 9) / 2f,
                    cy - 7, bold, 9, WHITE);

                // RISCO
                String risk = dr.latest().getRiskLevel() != null
                        ? dr.latest().getRiskLevel().name() : "—";
                txt(risk, xCols[2] + 4, cy - 7, bold, 8, riskColor(risk));

                // DATA
                txt(dr.latest().getScannedAt().format(D_FMT),
                    xCols[3] + 4, cy - 7, normal, 8, TEXT);

                // MODO
                String modo    = dr.latest().isActiveMode() ? "ACTIVE" : "PASSIVE";
                float[] modCol = dr.latest().isActiveMode() ? ACCENT : MUTED;
                txt(modo, xCols[4] + 4, cy - 7, bold, 8, modCol);
            } else {
                txt("—", xCols[1] + 4, cy - 7, normal, 8, MUTED);
                txt("—", xCols[2] + 4, cy - 7, normal, 8, MUTED);
                txt("Never scanned", xCols[3] + 4, cy - 7, normal, 8, MUTED);
                txt("—", xCols[4] + 4, cy - 7, normal, 8, MUTED);
            }

            // VERIFICADO
            if (showVerified) {
                if (dr.verified()) {
                    txt("Verified", xCols[5] + 4, cy - 7, bold, 8, ACCENT);
                } else {
                    txt("Pending", xCols[5] + 4, cy - 7, normal, 8, MUTED);
                }
            }

            // Linha separadora
            fill(M, cy - rowH, CW, 0.3f, BORDER);
            cy -= rowH;
            alt = !alt;
        }
    }

    /** Substitui caracteres fora do WinAnsi (Latin-1) por equivalentes ASCII. */
    private String sanitize(String s) {
        if (s == null) return "-";
        return s.replace('—', '-')  // em-dash
                .replace('–', '-')  // en-dash
                .replace('‒', '-')  // figure dash
                .replace('‘', '\'').replace('’', '\'')
                .replace('“', '"').replace('”', '"')
                .replace('…', '.'); // ellipsis
    }

    // ── Helpers de layout ─────────────────────────────────────────────────────

    private void statBox(float x, float y, float w, float h,
                         String value, String label, float[] valueColor) throws IOException {
        fill(x, y - h, w, h, BGLIGHT);
        strokeRect(x, y - h, w, h, BORDER);
        float[] col = valueColor != null ? valueColor : TEXT;
        // Valor centrado verticalmente, label rente ao fundo
        txt(value, x + w / 2f - textWidth(value, bold, 20) / 2f,
            y - h / 2f + 6, bold, 20, col);
        txt(label, x + w / 2f - textWidth(label, normal, 8) / 2f,
            y - h + 10, normal, 8, MUTED);
    }

    private void sectionTitle(String title) throws IOException {
        need(28);
        fill(M, cy - 20, CW, 20, BGDARK);
        fill(M, cy - 20, 3, 20, ACCENT);
        txt(title, M + 10, cy - 7, bold, 9, ACCENT);
        cy -= 22;
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
        txt("CyberAudit · Executive Report  —  Confidential", M, 18, normal, 7, MUTED);
        txtR("Page " + pageNo, PW - M, 18, normal, 7, MUTED);
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

    // ── Records e enums internos ──────────────────────────────────────────────

    public enum ReportScope { DOMAINS, TEAM_SCANS, BOTH }

    private record DomainReport(
            String     host,       // hostname do domínio
            boolean    verified,   // true se domínio foi verificado
            ScanRecord latest,
            ScanResult result,
            ScanRecord previous
    ) {}

}
