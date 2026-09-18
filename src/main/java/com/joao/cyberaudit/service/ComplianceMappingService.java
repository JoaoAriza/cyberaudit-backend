package com.joao.cyberaudit.service;

import com.joao.cyberaudit.dto.ComplianceReport;
import com.joao.cyberaudit.dto.ComplianceReport.ComplianceItem;
import com.joao.cyberaudit.model.*;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * Mapeia os achados de segurança de um ScanResult para:
 *   - Artigos relevantes da LGPD (Lei 13.709/2018)
 *   - Controles da ISO/IEC 27001:2022 (Anexo A)
 *
 * Lógica: cada controle é avaliado individualmente a partir dos campos do ScanResult.
 * Status: PASS | FAIL | WARN | NA
 *
 * <p>O texto — título do controle, o requisito da norma, a recomendação e cada
 * não-conformidade — vem do {@link MessageCatalog}. Nasceu chumbado em português
 * aqui, e este é o módulo que mais texto corrido produz: o cliente que lia a tela
 * em inglês recebia o relatório de conformidade inteiro em português.
 *
 * <p>A referência do controle ({@code Art. 46}, {@code A.8.7}) fica literal de
 * propósito: é a citação da norma, igual em qualquer idioma. O que muda é a
 * chave do catálogo, que não pode ter ponto no meio — daí o par
 * {@code ("Art. 46", "LGPD_46")} em cada item.
 */
@Service
public class ComplianceMappingService {

    private final MessageCatalog catalog;

    public ComplianceMappingService(MessageCatalog catalog) {
        this.catalog = catalog;
    }

    public ComplianceReport generate(ScanResult r) {
        List<ComplianceItem> lgpd = buildLgpd(r);
        List<ComplianceItem> iso  = buildIso(r);

        long lgpdFail = lgpd.stream().filter(i -> "FAIL".equals(i.getStatus())).count();
        long lgpdPass = lgpd.stream().filter(i -> "PASS".equals(i.getStatus())).count();
        long isoFail  = iso.stream().filter(i -> "FAIL".equals(i.getStatus())).count();
        long isoPass  = iso.stream().filter(i -> "PASS".equals(i.getStatus())).count();

        long total    = lgpd.size() + iso.size();
        long passed   = lgpdPass + isoPass;
        int  score    = total == 0 ? 100 : (int) Math.round((double) passed / total * 100);

        String risk;
        if (lgpdFail + isoFail == 0)           risk = "COMPLIANT";
        else if (lgpdFail + isoFail <= 2)      risk = "LOW";
        else if (lgpdFail + isoFail <= 5)      risk = "MEDIUM";
        else if (lgpdFail + isoFail <= 9)      risk = "HIGH";
        else                                   risk = "CRITICAL";

        return ComplianceReport.builder()
                .overallScore(score)
                .riskLevel(risk)
                .lgpdItems(lgpd)
                .isoItems(iso)
                .lgpdPassed(lgpdPass)
                .lgpdFailed(lgpdFail)
                .isoPassed(isoPass)
                .isoFailed(isoFail)
                .build();
    }

    // ── LGPD ─────────────────────────────────────────────────────────────────

    private List<ComplianceItem> buildLgpd(ScanResult r) {
        List<ComplianceItem> items = new ArrayList<>();

        // Art. 46 — Medidas de segurança, técnicas e administrativas
        {
            List<String> findings = new ArrayList<>();
            SSLInfo ssl = r.getSslInfo();
            TlsDetails tls = r.getTlsDetails();
            if (ssl != null && !ssl.isValid())
                findings.add(achado("TLS_INVALID"));
            if (tls != null && tls.isWeakProtocol())
                findings.add(achado("WEAK_TLS", tls.getNegotiatedProtocol()));
            if (!r.isRedirectsToHttps())
                findings.add(achado("NO_HTTPS_REDIRECT"));
            if (hasHeaderMissing(r, "Strict-Transport-Security"))
                findings.add(achado("HSTS_MISSING"));
            if (hasHeaderMissing(r, "Content-Security-Policy"))
                findings.add(achado("CSP_MISSING"));
            if (hasHeaderMissing(r, "X-Frame-Options"))
                findings.add(achado("XFRAME_MISSING"));

            items.add(item("Art. 46", "LGPD_46", findings));
        }

        // Art. 47 — Garantia de confidencialidade por agentes
        {
            List<String> findings = new ArrayList<>();
            if (r.isServerVersionExposed())
                findings.add(achado("SERVER_VERSION"));
            if (r.isDbErrorLeakageSuspected())
                findings.add(achado("DB_ERROR"));
            if (notEmpty(r.getApiDocsExposure()))
                findings.add(achado("API_DOCS", r.getApiDocsExposure().size()));
            if (notEmpty(r.getSourceMapFindings()))
                findings.add(achado("SOURCE_MAPS"));

            items.add(item("Art. 47", "LGPD_47", findings));
        }

        // Art. 48 — Comunicação de incidentes de segurança
        {
            List<String> findings = new ArrayList<>();
            // Só afirma ausência quando o módulo concluiu: null é "não verificado",
            // e apontar não-conformidade a partir disso é inventar achado.
            if (Boolean.FALSE.equals(r.getSecurityTxtPresent()))
                findings.add(achado("SECURITY_TXT"));

            items.add(item("Art. 48", "LGPD_48", findings));
        }

        // Art. 49 — Segurança por padrão (privacy by design)
        {
            List<String> findings = new ArrayList<>();
            if (hasCookiesWithoutSecure(r))
                findings.add(achado("COOKIE_SECURE"));
            if (hasCookiesWithoutHttpOnly(r))
                findings.add(achado("COOKIE_HTTPONLY"));
            if (hasCookiesWithoutSameSite(r))
                findings.add(achado("COOKIE_SAMESITE"));
            if (r.isReflectedXssSuspected())
                findings.add(achado("XSS"));
            if (notEmpty(r.getPathTraversal()))
                findings.add(achado("TRAVERSAL", r.getPathTraversal().size()));

            items.add(item("Art. 49", "LGPD_49", findings));
        }

        // Art. 50 — Boas práticas e governança
        {
            List<String> findings = new ArrayList<>();
            DnsSecurityResult dns = r.getDnsSecurityResult();
            if (dns != null) {
                if (!dns.isSpfPresent())
                    findings.add(achado("SPF_MISSING"));
                if (!dns.isDmarcPresent())
                    findings.add(achado("DMARC_MISSING"));
                if (!dns.isCaaPresent())
                    findings.add(achado("CAA_MISSING"));
            }

            items.add(item("Art. 50", "LGPD_50", findings));
        }

        return items;
    }

    // ── ISO 27001:2022 ────────────────────────────────────────────────────────

    private List<ComplianceItem> buildIso(ScanResult r) {
        List<ComplianceItem> items = new ArrayList<>();

        // A.8.7 — Proteção contra malware
        {
            List<String> findings = new ArrayList<>();
            if (notEmpty(r.getCveFindings())) {
                long critical = r.getCveFindings().stream()
                        .filter(c -> c.getCvssScore() >= 9.0).count();
                findings.add(critical > 0
                        ? achado("CVES_CRITICAL", r.getCveFindings().size(), critical)
                        : achado("CVES", r.getCveFindings().size()));
            }
            items.add(item("A.8.7", "ISO_8_7", findings));
        }

        // A.8.9 — Gestão de configuração
        {
            List<String> findings = new ArrayList<>();
            if (r.isServerVersionExposed())
                findings.add(achado("SERVER_BANNER"));
            if (notEmpty(r.getDangerousHttpMethods())) {
                List<String> methods = r.getDangerousHttpMethods().stream()
                        .map(HttpMethodFinding::getMethod).toList();
                findings.add(achado("HTTP_METHODS", String.join(", ", methods)));
            }
            items.add(item("A.8.9", "ISO_8_9", findings));
        }

        // A.8.20 — Segurança de redes
        {
            List<String> findings = new ArrayList<>();
            if (notEmpty(r.getOpenPorts())) {
                // 80/443 são o próprio serviço web — estar aberto é o que coloca o
                // site no ar, não um desvio de controle. Só entram como não
                // conformidade as portas que não deveriam estar expostas na borda
                // (mesma regra que o ScoreService usa para não penalizar 80/443).
                List<String> ports = r.getOpenPorts().stream()
                        .filter(p -> p.getPort() != 80 && p.getPort() != 443)
                        .map(p -> p.getPort() + "/" + p.getService()).toList();
                if (!ports.isEmpty())
                    findings.add(achado("OPEN_PORTS", String.join(", ", ports)));
            }
            CorsResult cors = r.getCorsResult();
            if (cors != null && (cors.isWildcardOrigin() || cors.isReflectsOrigin()))
                findings.add(achado("CORS"));
            items.add(item("A.8.20", "ISO_8_20", findings));
        }

        // A.8.21 — Segurança de serviços de rede
        {
            List<String> findings = new ArrayList<>();
            SSLInfo ssl = r.getSslInfo();
            TlsDetails tls = r.getTlsDetails();
            if (ssl != null && !ssl.isValid())
                findings.add(achado("TLS_INVALID"));
            if (tls != null && tls.isWeakProtocol())
                findings.add(achado("TLS_OBSOLETE"));
            if (tls != null && tls.getCipherSuite() != null) {
                String cs = tls.getCipherSuite().toUpperCase();
                if (cs.contains("RC4") || cs.contains("DES") || cs.contains("3DES") || cs.contains("NULL"))
                    findings.add(achado("WEAK_CIPHER", tls.getCipherSuite()));
            }
            items.add(item("A.8.21", "ISO_8_21", findings));
        }

        // A.8.23 — Filtragem de conteúdo web
        {
            List<String> findings = new ArrayList<>();
            if (notEmpty(r.getOpenRedirectFindings()))
                findings.add(achado("OPEN_REDIRECT"));
            if (notEmpty(r.getHostHeaderFindings()))
                findings.add(achado("HOST_HEADER"));
            if (notEmpty(r.getCrlfFindings()))
                findings.add(achado("CRLF"));
            items.add(item("A.8.23", "ISO_8_23", findings));
        }

        // A.8.24 — Uso de criptografia
        {
            List<String> findings = new ArrayList<>();
            if (!r.isRedirectsToHttps())
                findings.add(achado("HTTP_NOT_REDIRECTED"));
            if (hasHeaderMissing(r, "Strict-Transport-Security"))
                findings.add(achado("HSTS_INITIAL"));
            items.add(item("A.8.24", "ISO_8_24", findings));
        }

        // A.8.25 — Ciclo de vida de desenvolvimento seguro
        {
            List<String> findings = new ArrayList<>();
            if (notEmpty(r.getGraphQlIntrospection())) {
                boolean introEnabled = r.getGraphQlIntrospection().stream()
                        .anyMatch(GraphQlIntrospectionFinding::isIntrospectionEnabled);
                if (introEnabled)
                    findings.add(achado("GRAPHQL"));
            }
            if (notEmpty(r.getApiDocsExposure()))
                findings.add(achado("API_DOCS_OPEN"));
            if (notEmpty(r.getSourceMapFindings()))
                findings.add(achado("SOURCE_MAPS_JS"));
            items.add(item("A.8.25", "ISO_8_25", findings));
        }

        // A.8.28 — Codificação segura
        {
            List<String> findings = new ArrayList<>();
            if (r.isReflectedXssSuspected())
                findings.add(achado("XSS_UNSANITIZED"));
            if (notEmpty(r.getPathTraversal()))
                findings.add(achado("TRAVERSAL_PARAMS"));
            if (notEmpty(r.getSsrfFindings()))
                findings.add(achado("SSRF"));
            if (r.isDbErrorLeakageSuspected())
                findings.add(achado("DB_ERROR_VISIBLE"));
            items.add(item("A.8.28", "ISO_8_28", findings));
        }

        // A.5.23 — Segurança da informação no uso de serviços em nuvem
        {
            List<String> findings = new ArrayList<>();
            if (notEmpty(r.getSubdomainTakeover())) {
                long vuln = r.getSubdomainTakeover().stream()
                        .filter(s -> "VULNERABLE".equals(s.getStatus())).count();
                if (vuln > 0)
                    findings.add(achado("TAKEOVER", vuln));
            }
            if (r.getCertTransparency() != null && r.getCertTransparency().isUnexpectedIssuer())
                findings.add(achado("UNEXPECTED_CA"));
            items.add(item("A.5.23", "ISO_5_23", findings));
        }

        // A.5.8 — Segurança da informação no gerenciamento de projetos
        {
            List<String> findings = new ArrayList<>();
            if (notEmpty(r.getJwtSecurity())) {
                long criticalJwt = r.getJwtSecurity().stream()
                        .filter(j -> "CRITICAL".equals(j.getSeverity()) || "HIGH".equals(j.getSeverity())).count();
                if (criticalJwt > 0)
                    findings.add(achado("JWT", criticalJwt));
            }
            items.add(item("A.5.8", "ISO_5_8", findings));
        }

        return items;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** Uma linha de não-conformidade, no idioma do laudo. */
    private String achado(String chave, Object... args) {
        return catalog.compliance("finding." + chave, args);
    }

    private ComplianceItem item(String ref, String chave, List<String> findings) {
        String status;
        if (findings.isEmpty())          status = "PASS";
        else                             status = "FAIL";

        return ComplianceItem.builder()
                .reference(ref)
                .title(catalog.compliance(chave + ".title"))
                .requirement(catalog.compliance(chave + ".requirement"))
                .status(status)
                .findings(findings)
                .recommendation(catalog.compliance(chave + ".recommendation"))
                .build();
    }

    private boolean hasHeaderMissing(ScanResult r, String headerName) {
        if (r.getHeaders() == null) return true;
        return r.getHeaders().keySet().stream()
                .noneMatch(k -> k.equalsIgnoreCase(headerName));
    }

    private boolean hasCookiesWithoutSecure(ScanResult r) {
        if (r.getCookieIssues() == null) return false;
        return r.getCookieIssues().stream()
                .anyMatch(c -> !c.isSecure());
    }

    private boolean hasCookiesWithoutHttpOnly(ScanResult r) {
        if (r.getCookieIssues() == null) return false;
        return r.getCookieIssues().stream()
                .anyMatch(c -> !c.isHttpOnly());
    }

    private boolean hasCookiesWithoutSameSite(ScanResult r) {
        if (r.getCookieIssues() == null) return false;
        return r.getCookieIssues().stream()
                .anyMatch(c -> c.getSameSite() == null || c.getSameSite().isBlank());
    }

    private boolean notEmpty(List<?> list) {
        return list != null && !list.isEmpty();
    }
}
