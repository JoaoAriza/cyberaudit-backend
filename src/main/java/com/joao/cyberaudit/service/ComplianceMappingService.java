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
 */
@Service
public class ComplianceMappingService {

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
                findings.add("Certificado TLS inválido ou expirado");
            if (tls != null && tls.isWeakProtocol())
                findings.add("Protocolo TLS fraco detectado (" + tls.getNegotiatedProtocol() + ")");
            if (!r.isRedirectsToHttps())
                findings.add("Site não redireciona HTTP → HTTPS");
            if (hasHeaderMissing(r, "Strict-Transport-Security"))
                findings.add("Header HSTS ausente");
            if (hasHeaderMissing(r, "Content-Security-Policy"))
                findings.add("Content-Security-Policy ausente");
            if (hasHeaderMissing(r, "X-Frame-Options"))
                findings.add("X-Frame-Options ausente (risco clickjacking)");

            items.add(item("Art. 46", "Segurança no tratamento de dados",
                    "O controlador e o operador devem adotar medidas de segurança, técnicas e administrativas "
                    + "aptas a proteger os dados pessoais de acessos não autorizados e de situações acidentais "
                    + "ou ilícitas de destruição, perda, alteração, comunicação ou difusão.",
                    findings, "Implemente TLS 1.2+, redirecione todo tráfego para HTTPS e configure os headers de segurança HTTP recomendados."));
        }

        // Art. 47 — Garantia de confidencialidade por agentes
        {
            List<String> findings = new ArrayList<>();
            if (r.isServerVersionExposed())
                findings.add("Versão do servidor exposta nos headers (facilita fingerprinting)");
            if (r.isDbErrorLeakageSuspected())
                findings.add("Possível vazamento de erros de banco de dados detectado");
            if (notEmpty(r.getApiDocsExposure()))
                findings.add("Documentação de API exposta publicamente (" + r.getApiDocsExposure().size() + " endpoints)");
            if (notEmpty(r.getSourceMapFindings()))
                findings.add("Source maps expostos — código-fonte acessível ao público");

            items.add(item("Art. 47", "Confidencialidade pelos agentes de tratamento",
                    "Os agentes de tratamento ou qualquer outra pessoa que intervenha em uma das fases do tratamento "
                    + "obriga-se a garantir a segurança da informação e manter o sigilo dos dados pessoais.",
                    findings, "Remova headers que expõem versão do software, oculte mensagens de erro internas e restrinja acesso a documentação de API."));
        }

        // Art. 48 — Comunicação de incidentes de segurança
        {
            List<String> findings = new ArrayList<>();
            if (!r.isSecurityTxtPresent())
                findings.add("Arquivo security.txt ausente — sem canal formal de reporte de vulnerabilidades");

            items.add(item("Art. 48", "Comunicação de incidentes à autoridade nacional",
                    "O controlador deverá comunicar à autoridade nacional e ao titular a ocorrência de incidente de "
                    + "segurança que possa acarretar risco ou dano relevante aos titulares.",
                    findings, "Publique um arquivo security.txt em /.well-known/security.txt com contato de segurança e política de divulgação responsável."));
        }

        // Art. 49 — Segurança por padrão (privacy by design)
        {
            List<String> findings = new ArrayList<>();
            if (hasCookiesWithoutSecure(r))
                findings.add("Cookies sem flag Secure — transmitidos em conexões HTTP");
            if (hasCookiesWithoutHttpOnly(r))
                findings.add("Cookies sem flag HttpOnly — acessíveis via JavaScript");
            if (hasCookiesWithoutSameSite(r))
                findings.add("Cookies sem atributo SameSite — vulneráveis a CSRF");
            if (r.isReflectedXssSuspected())
                findings.add("Indício de XSS refletido detectado");
            if (notEmpty(r.getPathTraversal()))
                findings.add("Path traversal / LFI detectado (" + r.getPathTraversal().size() + " parâmetros)");

            items.add(item("Art. 49", "Segurança por padrão (Privacy by Design)",
                    "Os sistemas utilizados para o tratamento de dados pessoais deverão ser estruturados de forma "
                    + "a atender aos requisitos de segurança, padrões de boas práticas e de governança e aos "
                    + "princípios gerais previstos nesta Lei.",
                    findings, "Aplique flags Secure, HttpOnly e SameSite=Strict em todos os cookies de sessão. Valide e sanitize todas as entradas do usuário."));
        }

        // Art. 50 — Boas práticas e governança
        {
            List<String> findings = new ArrayList<>();
            DnsSecurityResult dns = r.getDnsSecurityResult();
            if (dns != null) {
                if (!dns.isSpfPresent())
                    findings.add("SPF ausente — domínio vulnerável a spoofing de email");
                if (!dns.isDmarcPresent())
                    findings.add("DMARC ausente — sem política de autenticação de email");
                if (!dns.isCaaPresent())
                    findings.add("CAA ausente — qualquer CA pode emitir certificado para o domínio");
            }

            items.add(item("Art. 50", "Boas práticas e governança de dados",
                    "Os controladores e operadores, no âmbito de suas competências, pelo tratamento de dados "
                    + "pessoais, poderão formular regras de boas práticas e de governança que estabeleçam as "
                    + "condições de organização, o regime de funcionamento.",
                    findings, "Configure registros SPF, DMARC (política reject/quarantine) e CAA no DNS do domínio."));
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
                findings.add(r.getCveFindings().size() + " CVE(s) detectadas"
                        + (critical > 0 ? " (" + critical + " críticas)" : ""));
            }
            items.add(item("A.8.7", "Proteção contra malware",
                    "Implantação de proteções contra malware com gestão centralizada de detecção e resposta.",
                    findings, "Atualize todos os componentes com CVEs conhecidos. Implante WAF e monitoramento de integridade de arquivos."));
        }

        // A.8.9 — Gestão de configuração
        {
            List<String> findings = new ArrayList<>();
            if (r.isServerVersionExposed())
                findings.add("Banner do servidor expõe versão — facilita ataques direcionados");
            if (notEmpty(r.getDangerousHttpMethods())) {
                List<String> methods = r.getDangerousHttpMethods().stream()
                        .map(HttpMethodFinding::getMethod).toList();
                findings.add("Métodos HTTP perigosos habilitados: " + String.join(", ", methods));
            }
            items.add(item("A.8.9", "Gestão de configuração",
                    "As configurações, incluindo configurações de segurança, de hardware, software, serviços e redes "
                    + "devem ser estabelecidas, documentadas, implementadas, monitoradas e revisadas.",
                    findings, "Desabilite métodos HTTP desnecessários (PUT, DELETE, TRACE). Remova headers que expõem versão de software."));
        }

        // A.8.20 — Segurança de redes
        {
            List<String> findings = new ArrayList<>();
            if (notEmpty(r.getOpenPorts())) {
                List<String> ports = r.getOpenPorts().stream()
                        .map(p -> p.getPort() + "/" + p.getService()).toList();
                findings.add("Portas abertas: " + String.join(", ", ports));
            }
            CorsResult cors = r.getCorsResult();
            if (cors != null && (cors.isWildcardOrigin() || cors.isReflectsOrigin()))
                findings.add("CORS mal configurado — permite origens arbitrárias");
            items.add(item("A.8.20", "Segurança de redes",
                    "As redes e os dispositivos de rede devem ser protegidos, gerenciados e controlados para "
                    + "proteger as informações nos sistemas e aplicações.",
                    findings, "Feche portas desnecessárias via firewall. Restrinja a política CORS para origens confiáveis explícitas."));
        }

        // A.8.21 — Segurança de serviços de rede
        {
            List<String> findings = new ArrayList<>();
            SSLInfo ssl = r.getSslInfo();
            TlsDetails tls = r.getTlsDetails();
            if (ssl != null && !ssl.isValid())
                findings.add("Certificado TLS inválido ou expirado");
            if (tls != null && tls.isWeakProtocol())
                findings.add("TLS 1.0/1.1 ativo — protocolos obsoletos e inseguros");
            if (tls != null && tls.getCipherSuite() != null) {
                String cs = tls.getCipherSuite().toUpperCase();
                if (cs.contains("RC4") || cs.contains("DES") || cs.contains("3DES") || cs.contains("NULL"))
                    findings.add("Cipher suite fraca em uso: " + tls.getCipherSuite());
            }
            items.add(item("A.8.21", "Segurança de serviços de rede",
                    "Os mecanismos de segurança, níveis de serviço e requisitos de gerenciamento de todos os "
                    + "serviços de rede devem ser identificados, implementados e monitorados.",
                    findings, "Desabilite TLS 1.0/1.1 e cipher suites fracas. Mantenha apenas TLS 1.2 e 1.3 com ciphers AEAD."));
        }

        // A.8.23 — Filtragem de conteúdo web
        {
            List<String> findings = new ArrayList<>();
            if (notEmpty(r.getOpenRedirectFindings()))
                findings.add("Open redirect detectado — pode ser explorado em phishing");
            if (notEmpty(r.getHostHeaderFindings()))
                findings.add("Host header injection — permite cache poisoning e redirecionamentos");
            if (notEmpty(r.getCrlfFindings()))
                findings.add("CRLF injection detectado — permite HTTP response splitting");
            items.add(item("A.8.23", "Filtragem de conteúdo web",
                    "O acesso a sites externos deve ser gerenciado para reduzir a exposição a conteúdo malicioso.",
                    findings, "Valide o header Host no backend. Bloqueie injeção de CR/LF e sanitize parâmetros de redirecionamento."));
        }

        // A.8.24 — Uso de criptografia
        {
            List<String> findings = new ArrayList<>();
            if (!r.isRedirectsToHttps())
                findings.add("Tráfego HTTP não redirecionado para HTTPS");
            if (hasHeaderMissing(r, "Strict-Transport-Security"))
                findings.add("HSTS ausente — browser pode fazer requisição HTTP inicial");
            items.add(item("A.8.24", "Uso de criptografia",
                    "As regras para o uso efetivo de criptografia, incluindo o gerenciamento de chaves "
                    + "criptográficas, devem ser definidas e implementadas.",
                    findings, "Force HTTPS em toda a aplicação. Implemente HSTS com max-age mínimo de 1 ano e preload."));
        }

        // A.8.25 — Ciclo de vida de desenvolvimento seguro
        {
            List<String> findings = new ArrayList<>();
            if (notEmpty(r.getGraphQlIntrospection())) {
                boolean introEnabled = r.getGraphQlIntrospection().stream()
                        .anyMatch(GraphQlIntrospectionFinding::isIntrospectionEnabled);
                if (introEnabled)
                    findings.add("GraphQL introspection habilitada em produção — expõe schema completo");
            }
            if (notEmpty(r.getApiDocsExposure()))
                findings.add("Documentação de API (Swagger/OpenAPI) acessível sem autenticação");
            if (notEmpty(r.getSourceMapFindings()))
                findings.add("Source maps expostos — código-fonte JavaScript acessível");
            items.add(item("A.8.25", "Ciclo de vida de desenvolvimento seguro",
                    "As regras para o desenvolvimento seguro de software e sistemas devem ser estabelecidas "
                    + "e aplicadas.",
                    findings, "Desabilite introspection GraphQL em produção. Proteja documentação de API com autenticação. Não publique source maps."));
        }

        // A.8.28 — Codificação segura
        {
            List<String> findings = new ArrayList<>();
            if (r.isReflectedXssSuspected())
                findings.add("Indício de XSS refletido — entrada do usuário refletida sem sanitização");
            if (notEmpty(r.getPathTraversal()))
                findings.add("Path traversal / LFI detectado em parâmetros de entrada");
            if (notEmpty(r.getSsrfFindings()))
                findings.add("Server-Side Request Forgery (SSRF) detectado");
            if (r.isDbErrorLeakageSuspected())
                findings.add("Mensagens de erro de banco de dados visíveis na resposta");
            items.add(item("A.8.28", "Codificação segura",
                    "Os princípios de codificação segura devem ser aplicados ao desenvolvimento de software.",
                    findings, "Aplique validação de entrada em todas as camadas. Use prepared statements para SQL. Implemente Content Security Policy."));
        }

        // A.5.23 — Segurança da informação no uso de serviços em nuvem
        {
            List<String> findings = new ArrayList<>();
            if (notEmpty(r.getSubdomainTakeover())) {
                long vuln = r.getSubdomainTakeover().stream()
                        .filter(s -> "VULNERABLE".equals(s.getStatus())).count();
                if (vuln > 0)
                    findings.add(vuln + " subdomínio(s) vulneráveis a takeover via serviços em nuvem abandonados");
            }
            if (r.getCertTransparency() != null && r.getCertTransparency().isUnexpectedIssuer())
                findings.add("Certificado emitido por CA não esperada — possível comprometimento ou erro de configuração");
            items.add(item("A.5.23", "Segurança da informação no uso de serviços em nuvem",
                    "Os processos de aquisição, uso, gerenciamento e saída de serviços em nuvem devem ser "
                    + "estabelecidos de acordo com os requisitos de segurança da informação.",
                    findings, "Remova ou aponte corretamente registros DNS de serviços em nuvem descontinuados. Monitore emissão de certificados via CT logs."));
        }

        // A.5.8 — Segurança da informação no gerenciamento de projetos
        {
            List<String> findings = new ArrayList<>();
            if (notEmpty(r.getJwtSecurity())) {
                long criticalJwt = r.getJwtSecurity().stream()
                        .filter(j -> "CRITICAL".equals(j.getSeverity()) || "HIGH".equals(j.getSeverity())).count();
                if (criticalJwt > 0)
                    findings.add(criticalJwt + " problema(s) crítico(s) em tokens JWT (algoritmo fraco, sem expiração etc.)");
            }
            items.add(item("A.5.8", "Segurança da informação no gerenciamento de projetos",
                    "A segurança da informação deve ser integrada ao gerenciamento de projetos.",
                    findings, "Adote algoritmos assimétricos (RS256/ES256) em JWTs. Defina expiração curta e valide issuer/audience."));
        }

        return items;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private ComplianceItem item(String ref, String title, String requirement,
                                List<String> findings, String recommendation) {
        String status;
        if (findings.isEmpty())          status = "PASS";
        else                             status = "FAIL";

        return ComplianceItem.builder()
                .reference(ref)
                .title(title)
                .requirement(requirement)
                .status(status)
                .findings(findings)
                .recommendation(recommendation)
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
