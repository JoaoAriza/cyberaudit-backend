package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.*;
import org.apache.pdfbox.pdmodel.*;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.*;
import org.apache.pdfbox.pdmodel.graphics.color.*;
import org.springframework.stereotype.Service;

import java.io.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class PdfReportService {

    // ── Layout constants ──────────────────────────────────────────────────────
    private static final float M  = 45f;
    private static final float LH = 13f;
    private static final float PH = PDRectangle.A4.getHeight();   // 841.89
    private static final float PW = PDRectangle.A4.getWidth();    // 595.28
    private static final float CW = PW - 2 * M;                   // ~505

    // ── Color palette (R G B, range 0-1) ─────────────────────────────────────
    private static final float[] NAVY    = {0.05f, 0.08f, 0.12f};
    private static final float[] DARK    = {0.09f, 0.13f, 0.19f};
    private static final float[] ACCENT  = {0f,    0.83f, 0.63f};
    private static final float[] WHITE   = {1f,    1f,    1f};
    private static final float[] TEXT    = {0.12f, 0.16f, 0.22f};
    private static final float[] MUTED   = {0.42f, 0.50f, 0.58f};
    private static final float[] BORDER  = {0.86f, 0.89f, 0.92f};
    private static final float[] BGLIGHT = {0.96f, 0.97f, 0.98f};
    private static final float[] CRIT    = {0.84f, 0.10f, 0.10f};
    private static final float[] HIGH    = {0.89f, 0.40f, 0.05f};
    private static final float[] MED     = {0.76f, 0.52f, 0.04f};
    private static final float[] LOW_C   = {0.18f, 0.44f, 0.76f};
    private static final float[] INFO_C  = {0.44f, 0.53f, 0.62f};
    private static final float[] OK      = {0.05f, 0.60f, 0.36f};

    // ── Per-call state ────────────────────────────────────────────────────────
    private PDDocument doc;
    private PDPageContentStream cs;
    private float cy;
    private int   pageNo;
    private PDType1Font bold, normal, mono;

    // ── Entry point ───────────────────────────────────────────────────────────

    public byte[] generatePdf(ScanResult r, String ignored) {
        try {
            doc    = new PDDocument();
            bold   = PDType1Font.HELVETICA_BOLD;
            normal = PDType1Font.HELVETICA;
            mono   = PDType1Font.COURIER;
            pageNo = 0;
            cs     = null;

            openPage();
            coverHeader(r);
            summaryBox(r);
            renderSections(r);
            closePage();

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            doc.save(out);
            doc.close();
            return out.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException("PDF error: " + e.getMessage(), e);
        }
    }

    private void renderSections(ScanResult r) throws IOException {
        // 1. Issues (critical first)
        if (hasIssues(r)) issuesSection(r);
        // 2. CVE dedicated
        if (r.getCveFindings() != null && r.getCveFindings().stream().anyMatch(c -> c.getCvssScore() >= 7.0))
            cveSection(r);
        // 3. Transport
        transportSection(r);
        // 4. Headers
        if (r.getHeaders() != null && !r.getHeaders().isEmpty()) headersSection(r);
        // 5. Technology
        if (r.getTechFingerprint() != null) techSection(r);
        // 6. DNS
        if (r.getDnsSecurityResult() != null) dnsSection(r);
        // 7. Cert Transparency
        if (r.getCertTransparency() != null) certSection(r);
        // 8. Subdomain Takeover
        if (r.getSubdomainTakeover() != null && !r.getSubdomainTakeover().isEmpty()) takeoverSection(r);
        // 9. Cookies
        if (r.getCookieIssues() != null && !r.getCookieIssues().isEmpty()) cookieSection(r);
        // 10. HTTP Methods
        if (r.getDangerousHttpMethods() != null && !r.getDangerousHttpMethods().isEmpty()) methodsSection(r);
        // 11. Open Redirect
        if (r.getOpenRedirectFindings() != null && r.getOpenRedirectFindings().stream().anyMatch(OpenRedirectFinding::isVulnerable))
            redirectSection(r);
        // 12. Directory Listing
        if (r.getDirectoryListingFindings() != null && r.getDirectoryListingFindings().stream().anyMatch(DirectoryListingFinding::isListingEnabled))
            dirListSection(r);
        // 13. Open Ports
        if (r.getOpenPorts() != null && !r.getOpenPorts().isEmpty()) portsSection(r);
        // 14. Active checks
        if (r.isActiveMode() && (r.isInputSurfaceDetected() || r.isDbErrorLeakageSuspected() || r.isReflectedXssSuspected()))
            activeSection(r);
        // 15. CORS
        if (r.getCorsResult() != null && r.getCorsResult().isTested()
                && (r.getCorsResult().isWildcardOrigin() || r.getCorsResult().isReflectsOrigin()
                    || r.getCorsResult().isCredentialsAllowed()))
            corsSection(r);
        // 16. JWT Security
        if (r.getJwtSecurity() != null && !r.getJwtSecurity().isEmpty()) jwtSection(r);
        // 17. GraphQL Introspection
        if (r.getGraphQlIntrospection() != null && !r.getGraphQlIntrospection().isEmpty()) graphQlSection(r);
        // 18. API Docs Exposure
        if (r.getApiDocsExposure() != null && !r.getApiDocsExposure().isEmpty()) apiDocsSection(r);
        // 19. Changes
        if (r.getChanges() != null && !r.getChanges().isEmpty()) changesSection(r);
        // 20. Score breakdown
        if (r.getScore() != null && r.getScore().getNotes() != null && !r.getScore().getNotes().isEmpty())
            scoreBreakdown(r);
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
        // Footer line
        fill(M, 28, CW, 0.5f, BORDER);
        txt("CyberAudit Security Report  —  Confidential", M, 18, normal, 7, MUTED);
        txtR("Page " + pageNo, PW - M, 18, normal, 7, MUTED);
        cs.close();
    }

    private void need(float h) throws IOException {
        if (cy - h < 55) {
            closePage();
            openPage();
        }
    }

    // ── Cover header ──────────────────────────────────────────────────────────

    private void coverHeader(ScanResult r) throws IOException {
        fill(0, PH - 85, PW, 85, NAVY);
        fill(0, PH - 85, 4,  85, ACCENT);
        txt("CYBERAUDIT", M + 8, PH - 34, bold, 22, ACCENT);
        txt("Web Security Report", M + 8, PH - 52, normal, 11, WHITE);
        String date = LocalDateTime.now().format(DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm"));
        txtR("Generated: " + date, PW - M, PH - 38, normal, 8, MUTED);
        txtR("CONFIDENTIAL", PW - M, PH - 52, bold, 7, MUTED);
        cy = PH - 100;
    }

    private void summaryBox(ScanResult r) throws IOException {
        float boxH = 82;
        fill(M, cy - boxH, CW, boxH, BGLIGHT);
        strokeRect(M, cy - boxH, CW, boxH, BORDER);
        fill(M, cy - boxH, 3, boxH, ACCENT);

        String url = s(r.getFinalUrl() != null ? r.getFinalUrl() : r.getUrl());
        txt("TARGET", M + 12, cy - 12, bold, 7, MUTED);
        wrapTxt(url, M + 12, cy - 24, mono, 9, TEXT, CW / 2);

        // Scan type + status (right side, before cy update)
        String scanType = r.isActiveMode() ? "ACTIVE SCAN" : "PASSIVE SCAN";
        txtR(scanType, PW - M - 12, cy - 14, bold, 8, MUTED);
        if (r.getHttpStatus() > 0)
            txtR("HTTP " + r.getHttpStatus(), PW - M - 12, cy - 27, normal, 9, TEXT);

        if (r.getScore() != null) {
            int score = r.getScore().getScore();
            String risk = r.getScore().getRiskLevel() != null ? r.getScore().getRiskLevel().name() : "UNKNOWN";
            float[] rc  = riskColor(risk);
            txt("SCORE", M + 12, cy - 42, bold, 7, MUTED);
            txt(score + " / 100", M + 12, cy - 57, bold, 20, rc);
            float bx = M + 12 + sw(score + " / 100", bold, 20) + 12;
            float[] bgc = riskBg(risk);
            float bw = sw(risk, bold, 8) + 14;
            fill(bx, cy - 65, bw, 15, bgc);
            txt(risk, bx + 7, cy - 56, bold, 8, rc);
        }
        cy -= boxH + 12;

        // Severity distribution bar
        if (hasIssues(r)) severityDist(r.getScore().getIssues());
        cy -= 10;
    }

    private void severityDist(List<SecurityIssue> issues) throws IOException {
        long nc = issues.stream().filter(i -> "CRITICAL".equals(i.getSeverity())).count();
        long nh = issues.stream().filter(i -> "HIGH".equals(i.getSeverity())).count();
        long nm = issues.stream().filter(i -> "MEDIUM".equals(i.getSeverity())).count();
        long nl = issues.stream().filter(i -> "LOW".equals(i.getSeverity())).count();
        long tot = nc + nh + nm + nl;
        if (tot == 0) return;

        txt("SEVERITY DISTRIBUTION", M, cy - 2, bold, 7, MUTED);
        cy -= 13;

        float bx = M, bh = 9;
        fill(bx, cy - bh, CW, bh, BORDER);
        if (nc > 0) { float w = CW * nc / tot; fill(bx, cy - bh, w, bh, CRIT); bx += w; }
        if (nh > 0) { float w = CW * nh / tot; fill(bx, cy - bh, w, bh, HIGH); bx += w; }
        if (nm > 0) { float w = CW * nm / tot; fill(bx, cy - bh, w, bh, MED);  bx += w; }
        if (nl > 0) { float w = CW * nl / tot; fill(bx, cy - bh, w, bh, LOW_C); }
        cy -= 13;

        bx = M;
        if (nc > 0) { bx = legend(bx, cy, CRIT,  "CRITICAL " + nc); bx += 14; }
        if (nh > 0) { bx = legend(bx, cy, HIGH,  "HIGH "     + nh); bx += 14; }
        if (nm > 0) { bx = legend(bx, cy, MED,   "MEDIUM "   + nm); bx += 14; }
        if (nl > 0) {      legend(bx, cy, LOW_C, "LOW "       + nl); }
        cy -= 14;
    }

    private float legend(float x, float y, float[] col, String label) throws IOException {
        fill(x, y - 6, 7, 7, col);
        txt(label, x + 11, y, normal, 8, MUTED);
        return x + 11 + sw(label, normal, 8);
    }

    // ── Section header ────────────────────────────────────────────────────────

    private void secHead(String title) throws IOException {
        need(35);
        cy -= 10;
        fill(M,     cy - 18, CW, 18, DARK);
        fill(M,     cy - 18, 3,  18, ACCENT);
        txt(title,  M + 10,  cy - 13, bold, 9, WHITE);
        cy -= 30;  // 18px header + 12px gap (4pt clearance above bold cap-height)
    }

    // ── Key-value rows ────────────────────────────────────────────────────────

    private void kv(String key, String val) throws IOException { kv(key, val, TEXT); }

    private void kv(String key, String val, float[] col) throws IOException {
        if (val == null || val.isBlank()) return;
        int lines = lineCount(s(val), normal, 9, CW - 155);
        need(LH * lines + 4);
        txt(key.toUpperCase(), M + 8, cy, normal, 7, MUTED);
        float lastY = wrapTxt(s(val), M + 155, cy, normal, 9, col, CW - 155);
        cy = lastY - LH - 1;
    }

    private void kvBool(String key, boolean val, boolean goodIfTrue) throws IOException {
        kv(key, val ? "YES" : "NO", val == goodIfTrue ? OK : CRIT);
    }

    private void sep() throws IOException {
        need(8);
        fill(M + 8, cy - 2, CW - 16, 0.4f, BORDER);
        cy -= 8;
    }

    // ── Issue row ─────────────────────────────────────────────────────────────

    private void issueRow(SecurityIssue issue) throws IOException {
        // Estimate height before drawing
        int titleLines  = lineCount(s(issue.getTitle()), bold, 9, CW - 74);
        int impactLines = issue.getImpact() != null && !issue.getImpact().isBlank()
                ? lineCount(s(issue.getImpact()), normal, 8, CW - 60) : 0;
        String rec0 = issue.getRecommendation() != null
                ? issue.getRecommendation().replaceAll("\\s*Ref:\\s*https?://\\S+", "").trim() : "";
        int fixLines = !rec0.isBlank() ? lineCount(s(rec0), normal, 8, CW - 60) : 0;
        int totalLines = 1 + titleLines + (impactLines > 0 ? impactLines : 0) + (fixLines > 0 ? fixLines : 0);
        need(LH * totalLines + 14);

        float[] sc = sevColor(issue.getSeverity());
        float[] sb = sevBg(issue.getSeverity());
        float startY = cy;

        // Fixed-width badge (58px) → titles always start at M+74 regardless of severity label
        final float FBW = 58f;
        final float TX  = M + 8 + FBW + 8;   // M+74 — fixed column for title and detail values
        fill(M + 8, cy - LH + 1, FBW, 11, sb);
        txt(issue.getSeverity(), M + 8 + (FBW - sw(issue.getSeverity(), bold, 7)) / 2f, cy - 2, bold, 7, sc);

        // Optional CVE label after fixed badge
        float titleX = TX;
        if (issue.getId() != null && issue.getId().startsWith("CVE_")) {
            fill(titleX, cy - LH + 1, 28, 11, new float[]{0.88f, 0.93f, 0.99f});
            txt("CVE", titleX + 5, cy - 2, bold, 7, LOW_C);
            titleX += 34;
        }

        float lastY = wrapTxt(s(issue.getTitle()), titleX, cy, bold, 9, TEXT, CW - (titleX - M));
        cy = lastY - LH + 1;

        // Impact / Fix: label near-left, value aligned with title column (TX)
        if (issue.getImpact() != null && !issue.getImpact().isBlank()) {
            txt("Impact", M + 12, cy, bold, 7, MUTED);
            lastY = wrapTxt(s(issue.getImpact()), TX, cy, normal, 8, MUTED, CW - (TX - M));
            cy = lastY - LH;
        }
        if (!rec0.isBlank()) {
            txt("Fix", M + 12, cy, bold, 7, MUTED);
            lastY = wrapTxt(s(rec0), TX, cy, normal, 8, MUTED, CW - (TX - M));
            cy = lastY - LH;
        }

        // Left severity bar drawn retroactively (x=M, no overlap with text at x=M+8+)
        fill(M, cy, 3, startY - cy + LH, sc);
        fill(M, cy - 1, CW, 0.3f, BORDER);
        cy -= 5;
    }

    // ── CVE row ───────────────────────────────────────────────────────────────

    private void cveRow(CVEFinding cve) throws IOException {
        need(LH * 3 + 12);
        float[] sc = sevColor(cve.getSeverity());
        float[] sb = sevBg(cve.getSeverity());

        fill(M, cy - LH * 3 - 5, CW, LH * 3 + 5,  BGLIGHT);  // top = cy

        final float FBW_CV = 58f;
        fill(M + 8, cy - LH + 1, FBW_CV, 11, sb);
        txt(cve.getSeverity(), M + 8 + (FBW_CV - sw(cve.getSeverity(), bold, 7)) / 2f, cy - 2, bold, 7, sc);

        float cx2 = M + 8 + FBW_CV + 8;
        txt(s(cve.getCveId()), cx2, cy, bold, 10, TEXT);
        float cx3 = cx2 + sw(s(cve.getCveId()), bold, 10) + 8;
        String cvssLabel = "CVSS " + String.format("%.1f", cve.getCvssScore());
        fill(cx3, cy - LH + 1, sw(cvssLabel, bold, 8) + 10, 12, sb);
        txt(cvssLabel, cx3 + 5, cy - 1, bold, 8, sc);
        cy -= LH + 3;

        if (cve.getAffectedSoftware() != null) {
            txt("Software", M + 14, cy, bold, 7, MUTED);
            txt(s(cve.getAffectedSoftware()), M + 65, cy, normal, 9, TEXT);
            cy -= LH;
        }
        if (cve.getDescription() != null && !cve.getDescription().isBlank()) {
            float lastDescY = wrapTxt(s(cve.getDescription()), M + 14, cy, normal, 8, MUTED, CW - 20);
            cy = lastDescY - LH;
        }
        if (cve.getPublishedDate() != null) {
            txt("Published", M + 14, cy, bold, 7, MUTED);
            txt(s(cve.getPublishedDate()), M + 65, cy, normal, 8, MUTED);
        }
        cy -= 8;
    }

    // ── Section renderers ─────────────────────────────────────────────────────

    private void issuesSection(ScanResult r) throws IOException {
        List<SecurityIssue> sorted = new ArrayList<>(r.getScore().getIssues());
        sorted.sort(Comparator.comparingInt(i -> sevOrder(i.getSeverity())));
        secHead("ISSUES  —  " + sorted.size() + " finding(s)");
        for (SecurityIssue i : sorted) issueRow(i);
        cy -= 6;
    }

    private void cveSection(ScanResult r) throws IOException {
        List<CVEFinding> cves = r.getCveFindings().stream()
                .filter(c -> c.getCvssScore() >= 7.0)
                .sorted((a, b) -> Double.compare(b.getCvssScore(), a.getCvssScore()))
                .collect(Collectors.toList());
        secHead("CVE CORRELATION  —  " + cves.size() + " vulnerability(ies)  (CVSS >= 7.0)");
        for (CVEFinding c : cves) cveRow(c);
        cy -= 6;
    }

    private void transportSection(ScanResult r) throws IOException {
        secHead("TRANSPORT SECURITY");
        if (r.getSslInfo() != null) {
            kvBool("HTTPS supported",   r.getSslInfo().isHttps(), true);
            kvBool("Certificate valid", r.getSslInfo().isValid(),  true);
            kv("Certificate expiration", o(r.getSslInfo().getExpirationDate()));
            kv("Days remaining",         o(r.getSslInfo().getDaysRemaining()));
        }
        kvBool("Redirects to HTTPS", r.isRedirectsToHttps(), true);
        if (r.getTlsDetails() != null) {
            TlsDetails tls = r.getTlsDetails();
            kv("TLS protocol",  tls.getNegotiatedProtocol());
            kv("Cipher suite",  tls.getCipherSuite());
            kvBool("Weak protocol", tls.isWeakProtocol(), false);
            if (tls.getMessage() != null && !tls.getMessage().isBlank())
                kv("Note", tls.getMessage());
        }
        cy -= 6;
    }

    private void headersSection(ScanResult r) throws IOException {
        secHead("SECURITY HEADERS");
        kv("Server version exposed", o(r.isServerVersionExposed()), r.isServerVersionExposed() ? CRIT : OK);
        for (Map.Entry<String, String> e : r.getHeaders().entrySet()) {
            kv(e.getKey(), e.getValue());
        }
        cy -= 6;
    }

    private void techSection(ScanResult r) throws IOException {
        TechFingerprintResult t = r.getTechFingerprint();
        if (t == null) return;
        boolean hasAny = t.getWebServer() != null || t.getBackend() != null || t.getFramework() != null
                || t.getCms() != null || t.getCdn() != null || t.getLanguage() != null
                || (t.getLibraries() != null && !t.getLibraries().isEmpty())
                || (t.getDetectedVersions() != null && !t.getDetectedVersions().isEmpty());
        if (!hasAny) return;
        secHead("TECHNOLOGY FINGERPRINT");
        kv("Web server", t.getWebServer());
        kv("Backend",    t.getBackend());
        kv("Framework",  t.getFramework());
        kv("CMS",        t.getCms());
        kv("CDN",        t.getCdn());
        kv("Language",   t.getLanguage());
        if (t.getLibraries() != null && !t.getLibraries().isEmpty())
            kv("Libraries", String.join(", ", t.getLibraries()));
        if (t.getDetectedVersions() != null && !t.getDetectedVersions().isEmpty()) {
            sep();
            txt("DETECTED VERSIONS", M + 8, cy, bold, 7, MUTED);
            cy -= LH + 2;
            for (Map.Entry<String, String> e : t.getDetectedVersions().entrySet())
                kv(e.getKey(), e.getValue());
        }
        cy -= 6;
    }

    private void dnsSection(ScanResult r) throws IOException {
        DnsSecurityResult dns = r.getDnsSecurityResult();
        if (dns == null) return;
        secHead("DNS SECURITY  /  RECONNAISSANCE");
        kv("SPF policy",   o(dns.getSpfPolicy()));
        kv("SPF record",   dns.getSpfRecord());
        kv("DMARC policy", o(dns.getDmarcPolicy()));
        kv("DMARC record", dns.getDmarcRecord());
        kvBool("DKIM found",  dns.isDkimHintFound(), true);
        if (dns.getDkimSelector() != null) kv("DKIM selector", dns.getDkimSelector());
        kvBool("CAA present", dns.isCaaPresent(), true);
        if (dns.getCaaRecord() != null) kv("CAA record", dns.getCaaRecord());
        if (dns.getMxRecords() != null && !dns.getMxRecords().isEmpty())
            kv("MX records", String.join(", ", dns.getMxRecords()));
        String risk = dns.getEmailSpoofingRisk();
        kv("Email spoofing risk", risk,
                "HIGH".equals(risk) ? CRIT : "MEDIUM".equals(risk) ? MED : OK);
        if (dns.getSummary() != null) kv("Summary", dns.getSummary());
        cy -= 6;
    }

    private void certSection(ScanResult r) throws IOException {
        CertTransparencyResult ct = r.getCertTransparency();
        if (ct == null) return;
        secHead("CERTIFICATE TRANSPARENCY");
        kv("Total certificates",  o(ct.getTotalCertificates()));
        kv("Unique subdomains",   o(ct.getUniqueSubdomains()));
        kv("Most recent issuance",ct.getMostRecentIssuance());
        kv("Oldest issuance",     ct.getOldestIssuance());
        kvBool("Wildcard detected",  ct.isWildcardDetected(), false);
        kvBool("Unexpected issuer",  ct.isUnexpectedIssuer(), false);
        kvBool("Recently issued",    ct.isRecentlyIssued(),   true);
        if (ct.getIssuers() != null && !ct.getIssuers().isEmpty())
            kv("Certificate issuers", String.join(", ", ct.getIssuers()));
        if (ct.getDiscoveredSubdomains() != null && !ct.getDiscoveredSubdomains().isEmpty()) {
            sep();
            txt("DISCOVERED SUBDOMAINS (" + ct.getDiscoveredSubdomains().size() + ")", M + 8, cy, bold, 7, MUTED);
            cy -= LH + 2;
            for (String sub : ct.getDiscoveredSubdomains()) {
                need(LH);
                txt("•  " + s(sub), M + 16, cy, mono, 8, TEXT);
                cy -= LH;
            }
        }
        cy -= 6;
    }

    private void takeoverSection(ScanResult r) throws IOException {
        secHead("SUBDOMAIN TAKEOVER");
        for (SubdomainTakeoverFinding f : r.getSubdomainTakeover()) {
            need(LH * 4 + 10);
            float[] sc = sevColor(f.getSeverity());
            float[] sb = sevBg(f.getSeverity());
            fill(M, cy - LH * 4 - 5, CW, LH * 4 + 5,  BGLIGHT);  // top = cy
            final float bw = 58f;
            fill(M + 8, cy - LH + 1, bw, 11, sb);
            txt(f.getSeverity(), M + 8 + (bw - sw(f.getSeverity(), bold, 7)) / 2f, cy - 2, bold, 7, sc);
            txt(s(f.getSubdomain()), M + 8 + bw + 8, cy, bold, 9, TEXT);
            cy -= LH + 3;
            kv("CNAME target",  f.getCnameTarget());
            kv("Service",       f.getService());
            kv("Status",        f.getStatus(), "VULNERABLE".equals(f.getStatus()) ? CRIT : MED);
            if (f.getVulnerability() != null) kv("Vulnerability", f.getVulnerability());
            cy -= 5;
        }
        cy -= 6;
    }

    private void cookieSection(ScanResult r) throws IOException {
        secHead("COOKIE SECURITY");
        for (CookieFinding cf : r.getCookieIssues()) {
            need(LH * 4 + 10);
            float[] sc = sevColor(cf.getRisk());
            float[] sb = sevBg(cf.getRisk());
            fill(M, cy - LH * 4 - 5, CW, LH * 4 + 5,  BGLIGHT);  // top = cy
            final float bw = 58f;
            fill(M + 8, cy - LH + 1, bw, 11, sb);
            txt(cf.getRisk(), M + 8 + (bw - sw(cf.getRisk(), bold, 7)) / 2f, cy - 2, bold, 7, sc);
            txt(s(cf.getName()), M + 8 + bw + 8, cy, bold, 9, TEXT);
            cy -= LH + 3;
            kv("HttpOnly", o(cf.isHttpOnly()), cf.isHttpOnly() ? OK : CRIT);
            kv("Secure",   o(cf.isSecure()),   cf.isSecure()   ? OK : CRIT);
            kv("SameSite", cf.getSameSite());
            if (cf.getIssues() != null && !cf.getIssues().isBlank()) kv("Issues", cf.getIssues());
            cy -= 5;
        }
        cy -= 6;
    }

    private void methodsSection(ScanResult r) throws IOException {
        secHead("DANGEROUS HTTP METHODS");
        for (HttpMethodFinding m : r.getDangerousHttpMethods()) {
            need(LH * 2 + 8);
            float[] sc = sevColor(m.getSeverity());
            final float bw = 58f;
            fill(M + 8, cy - LH + 1, bw, 11, sevBg(m.getSeverity()));
            txt(m.getSeverity(), M + 8 + (bw - sw(m.getSeverity(), bold, 7)) / 2f, cy - 2, bold, 7, sc);
            final float methTX = M + 8 + bw + 8;
            txt(s(m.getMethod()), methTX, cy, bold, 10, TEXT);
            txt("HTTP " + m.getStatusCode(), methTX + sw(s(m.getMethod()), bold, 10) + 8, cy, normal, 8, MUTED);
            cy -= LH + 3;
            if (m.getRisk() != null) kv("Risk", m.getRisk());
            cy -= 3;
        }
        cy -= 6;
    }

    private void redirectSection(ScanResult r) throws IOException {
        List<OpenRedirectFinding> vuln = r.getOpenRedirectFindings().stream()
                .filter(OpenRedirectFinding::isVulnerable).collect(Collectors.toList());
        if (vuln.isEmpty()) return;
        secHead("OPEN REDIRECT");
        for (OpenRedirectFinding f : vuln) {
            need(LH * 3 + 8);
            float[] sc = sevColor(f.getSeverity());
            final float bw = 58f;
            fill(M + 8, cy - LH + 1, bw, 11, sevBg(f.getSeverity()));
            txt(f.getSeverity(), M + 8 + (bw - sw(f.getSeverity(), bold, 7)) / 2f, cy - 2, bold, 7, sc);
            float lastRedY = wrapTxt(s(f.getTestedUrl()), M + 8 + bw + 8, cy, mono, 8, TEXT, CW - bw - 20);
            cy = lastRedY - LH + 1;
            kv("Redirected to", f.getRedirectedTo());
            kv("Parameter",     f.getParameter());
            cy -= 3;
        }
        cy -= 6;
    }

    private void dirListSection(ScanResult r) throws IOException {
        List<DirectoryListingFinding> on = r.getDirectoryListingFindings().stream()
                .filter(DirectoryListingFinding::isListingEnabled).collect(Collectors.toList());
        if (on.isEmpty()) return;
        secHead("DIRECTORY LISTING");
        for (DirectoryListingFinding f : on) {
            need(LH * 2 + 8);
            float[] sc = sevColor(f.getSeverity());
            final float bw = 58f;
            fill(M + 8, cy - LH + 1, bw, 11, sevBg(f.getSeverity()));
            txt(f.getSeverity(), M + 8 + (bw - sw(f.getSeverity(), bold, 7)) / 2f, cy - 2, bold, 7, sc);
            txt(s(f.getPath()), M + 8 + bw + 8, cy, mono, 9, TEXT);
            txtR("HTTP " + f.getStatusCode(), PW - M - 8, cy, normal, 8, MUTED);
            cy -= LH + 3;
            if (f.getEvidence() != null && !f.getEvidence().isBlank()) kv("Evidence", f.getEvidence());
            cy -= 3;
        }
        cy -= 6;
    }

    private void portsSection(ScanResult r) throws IOException {
        secHead("NETWORK EXPOSURE  —  " + r.getOpenPorts().size() + " open port(s)");
        for (PortFinding p : r.getOpenPorts()) {
            need(LH * 3 + 10);
            float[] sc = sevColor(p.getSeverity());
            final float bw = 58f;
            fill(M, cy - LH * 3 - 5, CW, LH * 3 + 5,  BGLIGHT);  // top = cy
            fill(M + 8, cy - LH + 1, bw, 11, sevBg(p.getSeverity()));
            txt(p.getSeverity(), M + 8 + (bw - sw(p.getSeverity(), bold, 7)) / 2f, cy - 2, bold, 7, sc);
            final float portTX = M + 8 + bw + 8;   // fixed column for port title
            txt("Port " + p.getPort(), portTX, cy, bold, 10, TEXT);
            txt(s(p.getService()), portTX + sw("Port " + p.getPort(), bold, 10) + 8, cy, normal, 9, MUTED);
            txtR("state: " + p.getState(), PW - M - 8, cy, normal, 8, MUTED);
            cy -= LH + 3;
            kv("Latency",        p.getLatencyMs() + " ms");
            kv("Impact",         p.getImpact());
            kv("Recommendation", p.getRecommendation());
            cy -= 5;
        }
        cy -= 6;
    }

    private void activeSection(ScanResult r) throws IOException {
        secHead("ACTIVE CHECKS");
        kv("Input surface detected",  o(r.isInputSurfaceDetected()),    r.isInputSurfaceDetected()    ? HIGH : OK);
        kv("DB error leakage",        o(r.isDbErrorLeakageSuspected()),  r.isDbErrorLeakageSuspected() ? CRIT : OK);
        kv("Reflected XSS suspected", o(r.isReflectedXssSuspected()),   r.isReflectedXssSuspected()   ? CRIT : OK);
        if (r.getWafDetectionResult() != null && r.getWafDetectionResult().isDetected()) {
            sep();
            WafDetectionResult waf = r.getWafDetectionResult();
            kv("WAF/CDN detected",  waf.getProvider(), OK);
            kv("WAF confidence",    waf.getConfidence());
            kv("Probe response",    waf.getProbeResponse());
            if (waf.getEvidence() != null) kv("Evidence", waf.getEvidence());
        }
        cy -= 6;
    }

    private void corsSection(ScanResult r) throws IOException {
        CorsResult c = r.getCorsResult();
        secHead("CORS ANALYSIS");
        kv("Allow-Origin",       c.getAllowOriginValue(), c.isWildcardOrigin() ? CRIT : TEXT);
        kvBool("Wildcard origin",      c.isWildcardOrigin(),     false);
        kvBool("Reflects origin",      c.isReflectsOrigin(),     false);
        kvBool("Credentials allowed",  c.isCredentialsAllowed(), false);
        kvBool("Null origin accepted", c.isNullOriginAccepted(), false);
        if (c.getMessage() != null) kv("Assessment", c.getMessage());
        cy -= 6;
    }


    private void jwtSection(ScanResult r) throws IOException {
        secHead("JWT SECURITY");
        for (JwtSecurityFinding jwt : r.getJwtSecurity()) {
            int rows = 3 + jwt.getIssues().size();
            need(LH * rows + 10);
            float[] sc = sevColor(jwt.getSeverity());
            float[] sb = sevBg(jwt.getSeverity());
            fill(M, cy - LH * rows - 5, CW, LH * rows + 5, BGLIGHT);
            final float FBW = 58f;
            final float TX  = M + 8 + FBW + 8;
            fill(M + 8, cy - LH + 1, FBW, 11, sb);
            txt(jwt.getSeverity(), M + 8 + (FBW - sw(jwt.getSeverity(), bold, 7)) / 2f, cy - 2, bold, 7, sc);
            txt(s(jwt.getSource()) + "  (alg=" + s(jwt.getAlgorithm()) + ")", TX, cy, bold, 9, TEXT);
            cy -= LH + 3;
            String expStr = !jwt.isHasExpiry() ? "MISSING" : jwt.isExpired() ? "EXPIRED" : "present";
            float[] expCol = !jwt.isHasExpiry() || jwt.isExpired() ? CRIT : OK;
            kv("Expiry",   expStr, expCol);
            kv("Issuer",   jwt.isHasIssuer()   ? "present" : "missing",
                    jwt.isHasIssuer()   ? OK : MED);
            kv("Audience", jwt.isHasAudience() ? "present" : "missing",
                    jwt.isHasAudience() ? OK : MED);
            if (jwt.getIssues() != null) {
                for (String issue : jwt.getIssues()) kv("Issue", issue);
            }
            cy -= 5;
        }
        cy -= 6;
    }

    private void graphQlSection(ScanResult r) throws IOException {
        secHead("GRAPHQL INTROSPECTION");
        for (GraphQlIntrospectionFinding gql : r.getGraphQlIntrospection()) {
            need(LH * 4 + 10);
            float[] sc = sevColor(gql.getSeverity());
            float[] sb = sevBg(gql.getSeverity());
            fill(M, cy - LH * 4 - 5, CW, LH * 4 + 5, BGLIGHT);
            final float FBW = 58f;
            final float TX  = M + 8 + FBW + 8;
            fill(M + 8, cy - LH + 1, FBW, 11, sb);
            txt(gql.getSeverity(), M + 8 + (FBW - sw(gql.getSeverity(), bold, 7)) / 2f, cy - 2, bold, 7, sc);
            txt(s(gql.getEndpoint()), TX, cy, bold, 9, TEXT);
            cy -= LH + 3;
            kv("Introspection", o(gql.isIntrospectionEnabled()),
                    gql.isIntrospectionEnabled() ? CRIT : OK);
            kv("Playground",    o(gql.isPlaygroundExposed()),
                    gql.isPlaygroundExposed() ? CRIT : OK);
            if (gql.getTypeCount() > 0)
                kv("Types exposed", String.valueOf(gql.getTypeCount()));
            if (gql.getEvidence() != null) kv("Evidence", gql.getEvidence());
            cy -= 5;
        }
        cy -= 6;
    }

    private void apiDocsSection(ScanResult r) throws IOException {
        secHead("API DOCUMENTATION EXPOSURE");
        for (ApiDocsExposureFinding f : r.getApiDocsExposure()) {
            need(LH * 3 + 10);
            float[] sc = sevColor(f.getSeverity());
            float[] sb = sevBg(f.getSeverity());
            fill(M, cy - LH * 3 - 5, CW, LH * 3 + 5, BGLIGHT);
            final float FBW = 58f;
            final float TX  = M + 8 + FBW + 8;
            fill(M + 8, cy - LH + 1, FBW, 11, sb);
            txt(f.getSeverity(), M + 8 + (FBW - sw(f.getSeverity(), bold, 7)) / 2f, cy - 2, bold, 7, sc);
            txt(s(f.getPath()), TX, cy, bold, 9, TEXT);
            cy -= LH + 3;
            kv("Type",     f.getType());
            kv("Evidence", f.getEvidence());
            if (f.getDescription() != null) kv("Risk", f.getDescription());
            cy -= 5;
        }
        cy -= 6;
    }

    private void changesSection(ScanResult r) throws IOException {
        secHead("CHANGES DETECTED  —  " + r.getChanges().size() + " change(s)");
        for (ScanChange ch : r.getChanges()) {
            need(LH * 3 + 10);
            float[] sc = sevColor(ch.getSeverity());
            final float bw = 58f;
            fill(M, cy - LH * 3 - 5, CW, LH * 3 + 5,  BGLIGHT);  // top = cy
            fill(M + 8, cy - LH + 1, bw, 11, sevBg(ch.getSeverity()));
            txt(ch.getSeverity(), M + 8 + (bw - sw(ch.getSeverity(), bold, 7)) / 2f, cy - 2, bold, 7, sc);
            final float chgTX = M + 8 + bw + 8;
            txt("[" + s(ch.getChangeType()) + "]", chgTX, cy, bold, 8, sc);
            txt(s(ch.getCategory()) + "  /  " + s(ch.getField()),
                    chgTX + sw("[" + ch.getChangeType() + "]", bold, 8) + 8, cy, normal, 8, TEXT);
            cy -= LH + 3;
            kv("Before", ch.getOldValue());
            kv("After",  ch.getNewValue(), OK);
            if (ch.getDescription() != null) kv("Note", ch.getDescription());
            cy -= 5;
        }
        cy -= 6;
    }

    private void scoreBreakdown(ScanResult r) throws IOException {
        List<String> notes = r.getScore().getNotes();
        secHead("SCORE BREAKDOWN");
        cy -= 4; // extra gap below section header
        txt("Starting score: 100 / 100", M + 8, cy, normal, 9, MUTED);
        cy -= LH + 6;
        for (String note : notes) {
            int noteLines = lineCount(s(note), normal, 9, CW - 22);
            need(LH * noteLines + 2);
            boolean deduction = note.contains(": -");
            float[] nc = deduction ? CRIT : OK;
            txt("•", M + 8, cy, normal, 9, nc);
            float lastNoteY = wrapTxt(s(note), M + 18, cy, normal, 9, nc, CW - 22);
            cy = lastNoteY - LH;
        }
        sep();
        txt("Final score: " + r.getScore().getScore() + " / 100  [" +
                (r.getScore().getRiskLevel() != null ? r.getScore().getRiskLevel().name() : "") + "]",
                M + 8, cy, bold, 11, riskColor(r.getScore().getRiskLevel() != null ? r.getScore().getRiskLevel().name() : ""));
        cy -= LH + 4;
    }

    // ── Low-level drawing helpers ─────────────────────────────────────────────

    private void fill(float x, float y, float w, float h, float[] col) throws IOException {
        cs.setNonStrokingColor(new PDColor(col, PDDeviceRGB.INSTANCE));
        cs.addRect(x, y, w, h);
        cs.fill();
    }

    private void strokeRect(float x, float y, float w, float h, float[] col) throws IOException {
        cs.setStrokingColor(new PDColor(col, PDDeviceRGB.INSTANCE));
        cs.setLineWidth(0.5f);
        cs.addRect(x, y, w, h);
        cs.stroke();
    }

    private void txt(String str, float x, float y, PDType1Font f, float sz, float[] col) throws IOException {
        if (str == null || str.isBlank()) return;
        cs.beginText();
        cs.setNonStrokingColor(new PDColor(col, PDDeviceRGB.INSTANCE));
        cs.setFont(f, sz);
        cs.newLineAtOffset(x, y);
        cs.showText(clip(str, 110));
        cs.endText();
    }

    private void txtR(String str, float rightX, float y, PDType1Font f, float sz, float[] col) throws IOException {
        if (str == null || str.isBlank()) return;
        float w = sw(str, f, sz);
        txt(str, rightX - w, y, f, sz, col);
    }

    // Returns y-baseline of the last line written
    private float wrapTxt(String text, float x, float y, PDType1Font f, float sz, float[] col, float maxW) throws IOException {
        if (text == null || text.isBlank()) return y;
        String[] words = text.split("\\s+");
        StringBuilder line = new StringBuilder();
        float curY = y;
        for (String word : words) {
            String test = line.length() == 0 ? word : line + " " + word;
            if (sw(test, f, sz) > maxW && line.length() > 0) {
                txt(line.toString(), x, curY, f, sz, col);
                curY -= LH;
                line = new StringBuilder(word);
            } else {
                line = new StringBuilder(test);
            }
        }
        if (line.length() > 0) txt(line.toString(), x, curY, f, sz, col);
        return curY;
    }

    // Count how many lines text will occupy at given width
    private int lineCount(String text, PDType1Font f, float sz, float maxW) {
        if (text == null || text.isBlank()) return 0;
        String[] words = text.split("\\s+");
        StringBuilder line = new StringBuilder();
        int count = 1;
        for (String word : words) {
            String test = line.length() == 0 ? word : line + " " + word;
            if (sw(test, f, sz) > maxW && line.length() > 0) { count++; line = new StringBuilder(word); }
            else { line = new StringBuilder(test); }
        }
        return count;
    }

    private float sw(String str, PDType1Font f, float sz) {
        if (str == null || str.isBlank()) return 0;
        try { return f.getStringWidth(str) / 1000f * sz; }
        catch (IOException e) { return str.length() * sz * 0.5f; }
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

    private boolean hasIssues(ScanResult r) {
        return r.getScore() != null && r.getScore().getIssues() != null && !r.getScore().getIssues().isEmpty();
    }

    private String s(String text) {
        if (text == null) return "";
        return text.replace("\r", "").replace("\t", "  ")
                .replace("ã","a").replace("â","a").replace("á","a").replace("à","a")
                .replace("ê","e").replace("é","e").replace("è","e")
                .replace("í","i").replace("î","i")
                .replace("õ","o").replace("ô","o").replace("ó","o").replace("ò","o")
                .replace("ú","u").replace("û","u").replace("ü","u")
                .replace("ç","c")
                .replace("Ã","A").replace("Â","A").replace("Á","A").replace("À","A")
                .replace("Ê","E").replace("É","E").replace("È","E")
                .replace("Í","I").replace("Î","I")
                .replace("Õ","O").replace("Ô","O").replace("Ó","O")
                .replace("Ú","U").replace("Û","U").replace("Ü","U")
                .replace("Ç","C")
                .replace("—","--").replace("–","-")
                .replace("’","'").replace("‘","'")
                .replace("“","\"").replace("”","\"")
                .replace("·",".").replace("•","*")
                .replaceAll("[^\\x00-\\x7E]","?");
    }

    private String o(Object obj) { return obj == null ? "" : obj.toString(); }

    private String clip(String str, int max) {
        return str.length() <= max ? str : str.substring(0, max - 3) + "...";
    }

    private float[] sevColor(String sev) {
        if (sev == null) return INFO_C;
        return switch (sev.toUpperCase()) {
            case "CRITICAL" -> CRIT;
            case "HIGH"     -> HIGH;
            case "MEDIUM"   -> MED;
            case "LOW"      -> LOW_C;
            default         -> INFO_C;
        };
    }

    private float[] sevBg(String sev) {
        if (sev == null) return new float[]{0.92f, 0.93f, 0.94f};
        return switch (sev.toUpperCase()) {
            case "CRITICAL" -> new float[]{0.98f, 0.91f, 0.91f};
            case "HIGH"     -> new float[]{0.99f, 0.94f, 0.89f};
            case "MEDIUM"   -> new float[]{0.99f, 0.97f, 0.87f};
            case "LOW"      -> new float[]{0.89f, 0.92f, 0.98f};
            default         -> new float[]{0.92f, 0.93f, 0.94f};
        };
    }

    private int sevOrder(String sev) {
        if (sev == null) return 4;
        return switch (sev.toUpperCase()) {
            case "CRITICAL" -> 0; case "HIGH" -> 1; case "MEDIUM" -> 2; case "LOW" -> 3; default -> 4;
        };
    }

    private float[] riskColor(String risk) {
        if (risk == null) return INFO_C;
        return switch (risk.toUpperCase()) {
            case "SECURE"   -> OK;
            case "WARNING"  -> MED;
            case "CRITICAL" -> CRIT;
            default         -> INFO_C;
        };
    }

    private float[] riskBg(String risk) {
        if (risk == null) return BGLIGHT;
        return switch (risk.toUpperCase()) {
            case "SECURE"   -> new float[]{0.89f, 0.98f, 0.93f};
            case "WARNING"  -> new float[]{0.99f, 0.97f, 0.87f};
            case "CRITICAL" -> new float[]{0.98f, 0.91f, 0.91f};
            default         -> BGLIGHT;
        };
    }
}
