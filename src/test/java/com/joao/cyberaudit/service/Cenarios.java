package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.*;
import java.util.*;

/** Cenario rico para auditar o laudo. */
class Cenarios {

    static ScanResult completo() {
        List<SecurityIssue> issues = new ArrayList<>();
        issues.add(issue("HIGH", "Certificado SSL invalido",
                "Usuarios recebem alerta de seguranca; comunicacao pode ser insegura.",
                "Renovar e configurar corretamente o certificado e a cadeia intermediaria."));
        issues.add(issue("LOW", "Permissions-Policy ausente",
                "Sem restricao de APIs de browser (camera, microfone, geolocalizacao).",
                "Adicionar Permissions-Policy restringindo features nao usadas."));
        issues.add(issue("LOW", "Versao de software exposta em Server ou X-Powered-By",
                "Facilita fingerprinting e busca por CVEs conhecidos.",
                "Remover ou obscurecer os headers Server e X-Powered-By."));
        issues.add(issue("LOW", "security.txt ausente (RFC 9116)",
                "Dificulta reporte responsavel de vulnerabilidades.",
                "Criar /.well-known/security.txt com campo Contact."));

        ScoreResult score = new ScoreResult();
        score.setScore(8);
        score.setRiskLevel(RiskLevel.CRITICAL);
        score.setIssues(issues);
        score.setNotes(List.of("Certificado invalido: -30", "Sem WAF: -5"));

        List<CVEFinding> cves = new ArrayList<>();
        cves.add(cve("CVE-2024-3566", "CRITICAL", 9.8, "PHP 7.4.33", "2024-04-10",
                "A command inject vulnerability allows an attacker to perform command injection on "
                + "Windows applications that indirectly depend on the CreateProcess function when "
                + "the specific conditions are satisfied."));
        cves.add(cve("CVE-2013-2220", "HIGH", 7.5, "PHP 7.4.33", "2013-07-31",
                "Buffer overflow in the radius_get_vendor_attr function in the Radius extension "
                + "before 1.2.7 for PHP allows remote RADIUS servers to cause a denial of service "
                + "and possibly execute arbitrary code via a large Vendor-Specific Attributes length value."));
        cves.add(cve("CVE-2008-1982", "HIGH", 7.5, "WordPress 3.7.1", "2008-04-27",
                "SQL injection vulnerability in ss_load.php in the Spreadsheet plugin 0.6 and "
                + "earlier for WordPress allows remote authenticated users to execute arbitrary "
                + "SQL commands via the ss_id parameter."));

        CookieFinding cookie = new CookieFinding();
        cookie.setName("PHPSESSID"); cookie.setRisk("HIGH");
        cookie.setHttpOnly(false); cookie.setSecure(false); cookie.setSameSite("None");
        cookie.setIssues("Sem HttpOnly (acessivel por JavaScript), sem Secure (trafega em texto "
                + "claro) e SameSite=None sem Secure, o que permite envio em requisicoes de terceiros.");

        ScanChange mudanca = new ScanChange();
        mudanca.setCategory("SSL"); mudanca.setField("certificate validity");
        mudanca.setChangeType("DEGRADED"); mudanca.setSeverity("HIGH");
        mudanca.setOldValue("valido"); mudanca.setNewValue("invalido");
        mudanca.setDescription("Certificado SSL tornou-se invalido entre o scan anterior e este, "
                + "o que costuma indicar expiracao sem renovacao automatica.");

        SubdomainTakeoverFinding takeover = new SubdomainTakeoverFinding();
        takeover.setSubdomain("staging.sgsistemas.com.br"); takeover.setSeverity("CRITICAL");
        takeover.setCnameTarget("unclaimed.github.io"); takeover.setService("GitHub Pages");
        takeover.setStatus("VULNERABLE");
        takeover.setVulnerability("CNAME aponta para um recurso nao reivindicado, o que permite "
                + "que um terceiro registre o destino e sirva conteudo no seu subdominio.");

        HttpMethodFinding metodo = new HttpMethodFinding();
        metodo.setMethod("TRACE"); metodo.setStatusCode(200);
        metodo.setEnabled(true); metodo.setSeverity("MEDIUM");
        metodo.setRisk("TRACE habilitado permite Cross-Site Tracing, que expoe cookies HttpOnly.");

        DirectoryListingFinding listagem = new DirectoryListingFinding();
        listagem.setPath("/uploads/"); listagem.setStatusCode(200);
        listagem.setListingEnabled(true); listagem.setSeverity("MEDIUM");
        listagem.setEvidence("Index of /uploads");

        OpenRedirectFinding redirect = new OpenRedirectFinding();
        redirect.setParameter("next"); redirect.setVulnerable(true); redirect.setSeverity("HIGH");
        redirect.setTestedUrl("http://sgsistemas.com.br/login?next=https://exemplo-malicioso.com/phishing");
        redirect.setRedirectedTo("https://exemplo-malicioso.com/phishing");

        PortFinding ftp = new PortFinding();
        ftp.setPort(21); ftp.setService("FTP"); ftp.setState("OPEN"); ftp.setSeverity("HIGH");
        ftp.setLatencyMs(182L);
        ftp.setImpact("FTP exposto: transmite credenciais em texto plano; permite enumeracao e exfiltracao de arquivos.");
        ftp.setRecommendation("Desative FTP. Use SFTP (porta 22) ou FTPS. Restrinja por firewall/VPN.");

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("strict-transport-security", "max-age=31536000; includeSubDomains");
        headers.put("content-security-policy", "default-src self; script-src self unsafe-inline https://cdn.exemplo.com");

        Map<String, String> modulos = new LinkedHashMap<>();
        modulos.put("HTTP_FETCH", "ERROR");

        return ScanResult.builder()
                .url("http://sgsistemas.com.br").finalUrl("http://sgsistemas.com.br")
                .httpStatus(200).activeMode(true)
                .score(score).cveFindings(cves).openPorts(List.of(ftp))
                .cookieIssues(List.of(cookie)).changes(List.of(mudanca))
                .subdomainTakeover(List.of(takeover)).dangerousHttpMethods(List.of(metodo))
                .directoryListingFindings(List.of(listagem)).openRedirectFindings(List.of(redirect))
                .headers(headers).moduleStatus(modulos)
                .build();
    }

    private static SecurityIssue issue(String sev, String t, String imp, String fix) {
        SecurityIssue i = new SecurityIssue();
        i.setSeverity(sev); i.setTitle(t); i.setImpact(imp); i.setRecommendation(fix);
        return i;
    }

    private static CVEFinding cve(String id, String sev, double cvss, String sw, String data, String desc) {
        CVEFinding c = new CVEFinding();
        c.setCveId(id); c.setSeverity(sev); c.setCvssScore(cvss);
        c.setAffectedSoftware(sw); c.setPublishedDate(data); c.setDescription(desc);
        return c;
    }
}
