package com.joao.cyberaudit.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.joao.cyberaudit.model.CertTransparencyResult;
import com.joao.cyberaudit.model.DnsSecurityResult;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Service
public class CertTransparencyService {

    private static final int  MAX_SUBDOMS  = 100;
    private static final int  RECENT_DAYS  = 7;
    private static final int  DISPLAY_DAYS = 30;

    /**
     * Certs emitidos antes de set/2017 não precisavam respeitar CAA (Ballot 187).
     * Janela de 2 anos cobre todos os certs modernos que deveriam respeitar CAA.
     */
    private static final LocalDate CAA_CHECK_CUTOFF = LocalDate.now().minusYears(2);

    /** Valor entre aspas de uma tag CAA — `issue "letsencrypt.org"` → letsencrypt.org. */
    private static final Pattern CAA_VALUE = Pattern.compile("\"([^\"]*)\"");

    /**
     * Domínio usado no CAA → trechos que aparecem no O= do certificado emitido.
     *
     * A comparação textual pura não fecha para a maioria das CAs: o domínio do
     * CAA é uma marca administrativa, não o nome no certificado. Sem esta
     * tabela, `pki.goog` nunca casa com "Google Trust Services" e todo
     * certificado legítimo vira alerta de emissão indevida.
     */
    private static final Map<String, List<String>> CAA_ISSUER_ALIASES = Map.ofEntries(
            Map.entry("letsencrypt.org",  List.of("let's encrypt", "lets encrypt",
                                                  "internet security research group", "isrg")),
            Map.entry("pki.goog",         List.of("google trust services", "google")),
            Map.entry("digicert.com",     List.of("digicert", "geotrust", "rapidssl",
                                                  "thawte", "verisign", "symantec")),
            Map.entry("sectigo.com",      List.of("sectigo", "comodo", "usertrust", "addtrust")),
            Map.entry("comodoca.com",     List.of("sectigo", "comodo", "usertrust", "addtrust")),
            Map.entry("ssl.com",          List.of("ssl.com", "ssl corp")),
            Map.entry("globalsign.com",   List.of("globalsign")),
            Map.entry("amazon.com",       List.of("amazon", "starfield")),
            Map.entry("amazontrust.com",  List.of("amazon", "starfield")),
            Map.entry("awstrust.com",     List.of("amazon", "starfield")),
            Map.entry("amazonaws.com",    List.of("amazon", "starfield")),
            Map.entry("godaddy.com",      List.of("godaddy", "go daddy", "starfield")),
            Map.entry("starfieldtech.com",List.of("starfield", "godaddy", "go daddy")),
            Map.entry("entrust.net",      List.of("entrust", "affirmtrust")),
            Map.entry("buypass.com",      List.of("buypass")),
            Map.entry("certum.pl",        List.of("certum", "asseco", "unizeto")),
            Map.entry("actalis.it",       List.of("actalis")),
            Map.entry("identrust.com",    List.of("identrust")),
            Map.entry("certainly.com",    List.of("certainly", "fastly")),
            Map.entry("pki.apple.com",    List.of("apple")),
            Map.entry("microsoft.com",    List.of("microsoft")),
            Map.entry("harica.gr",        List.of("harica", "hellenic academic")),
            Map.entry("firmaprofesional.com", List.of("firmaprofesional")),
            Map.entry("trustwave.com",    List.of("trustwave")),
            Map.entry("quovadisglobal.com", List.of("quovadis", "digicert"))
    );

    private final CrtShService crtShService; // ← compartilhado com SubdomainTakeoverService

    public CertTransparencyService(CrtShService crtShService) {
        this.crtShService = crtShService;
    }

    public CertTransparencyResult scan(String host, DnsSecurityResult dnsSecurityResult) {
        if (host == null || host.isBlank()) return emptyResult();

        // Usa CrtShService — retorna do cache se SubdomainTakeover já buscou
        List<JsonNode> rawCerts = crtShService.fetchCerts(host);
        if (rawCerts.isEmpty()) return emptyResult();

        Set<String> subdomains      = new LinkedHashSet<>();
        Set<String> allIssuers      = new LinkedHashSet<>();
        Set<String> recentIssuers   = new LinkedHashSet<>();
        Set<String> wildcardDomains = new LinkedHashSet<>();
        List<CertTransparencyResult.CertEntry> recentCerts = new ArrayList<>();

        String  mostRecent     = null;
        String  oldest         = null;
        boolean recentlyIssued = false;
        boolean wildcardDetected = false;

        LocalDate cutoff    = LocalDate.now().minusDays(DISPLAY_DAYS);
        LocalDate recentCut = LocalDate.now().minusDays(RECENT_DAYS);

        for (JsonNode cert : rawCerts) {
            String nameValue  = cert.path("name_value").asText("");
            String issuerName = cert.path("issuer_name").asText("").toLowerCase();
            String notBefore  = cert.path("not_before").asText("");
            String notAfter   = cert.path("not_after").asText("");
            String loggedAt   = cert.path("entry_timestamp").asText(notBefore);

            LocalDate issueDate = parseDate(notBefore);

            for (String name : nameValue.split("[\\n,]")) {
                name = name.trim().toLowerCase();
                if (name.isEmpty() || name.equals(host)) continue;
                if (name.startsWith("*.")) {
                    wildcardDetected = true;
                    wildcardDomains.add(name);
                    name = name.substring(2);
                }
                if (name.endsWith("." + host) || name.equals(host)) {
                    if (subdomains.size() < MAX_SUBDOMS) subdomains.add(name);
                }
            }

            String issuerClean = extractIssuerOrg(issuerName);
            if (!issuerClean.isBlank()) {
                allIssuers.add(issuerClean);
                if (issueDate != null && !issueDate.isBefore(CAA_CHECK_CUTOFF))
                    recentIssuers.add(issuerClean);
            }

            if (!notBefore.isBlank()) {
                if (mostRecent == null || notBefore.compareTo(mostRecent) > 0) mostRecent = notBefore;
                if (oldest    == null || notBefore.compareTo(oldest)     < 0) oldest     = notBefore;
            }

            if (issueDate != null) {
                if (!issueDate.isBefore(recentCut)) recentlyIssued = true;
                if (!issueDate.isBefore(cutoff) && recentCerts.size() < 10) {
                    recentCerts.add(CertTransparencyResult.CertEntry.builder()
                            .commonName(cert.path("common_name").asText(
                                    nameValue.split("[\\n,]")[0]))
                            .issuer(extractIssuerOrg(issuerName))
                            .notBefore(notBefore.split("T")[0])
                            .notAfter(notAfter.split("T")[0])
                            .wildcard(nameValue.contains("*."))
                            .loggedAt(loggedAt.split("T")[0])
                            .build());
                }
            }
        }

        List<String> unexpectedIssuers = detectUnexpectedIssuers(recentIssuers, dnsSecurityResult);

        List<String> discoveredSubdomains = subdomains.stream()
                .filter(s -> !s.equals(host)).sorted().limit(MAX_SUBDOMS)
                .collect(Collectors.toList());

        recentCerts.sort((a, b) -> b.getLoggedAt().compareTo(a.getLoggedAt()));

        return CertTransparencyResult.builder()
                .totalCertificates(rawCerts.size())
                .uniqueSubdomains(discoveredSubdomains.size())
                .mostRecentIssuance(mostRecent != null ? mostRecent.split("T")[0] : null)
                .oldestIssuance(oldest != null ? oldest.split("T")[0] : null)
                .recentlyIssued(recentlyIssued)
                .wildcardDetected(wildcardDetected)
                .unexpectedIssuer(!unexpectedIssuers.isEmpty())
                .discoveredSubdomains(discoveredSubdomains)
                .issuers(new ArrayList<>(allIssuers))
                .unexpectedIssuers(unexpectedIssuers)
                .wildcardDomains(new ArrayList<>(wildcardDomains))
                .recentCerts(recentCerts)
                .build();
    }

    private List<String> detectUnexpectedIssuers(Set<String> recentIssuers,
                                                 DnsSecurityResult dns) {
        if (dns == null || !dns.isCaaPresent()) return List.of();

        Set<String> authorizedDomains = parseCaaIssueDomains(dns);

        // Sem domínio nenhum extraído não dá para afirmar que um emissor é
        // indevido: pode ser CAA que só usa iodef, ou um formato que o parser
        // não entendeu. Acusar aqui gera alarme falso — o silêncio é correto.
        if (authorizedDomains.isEmpty()) return List.of();

        List<String> unexpected = new ArrayList<>();

        for (String issuer : recentIssuers) {
            String issuerLow = issuer.toLowerCase(Locale.ROOT).trim();
            if (issuerLow.isBlank() || issuerLow.equals("unknown")) continue;

            boolean authorized = authorizedDomains.stream()
                    .anyMatch(domain -> matchesCa(issuerLow, domain));

            if (!authorized) unexpected.add(issuer);
        }
        return unexpected;
    }

    /**
     * Extrai os domínios das tags `issue`/`issuewild` de todos os registros CAA.
     *
     * Entrada é o toString() do dnsjava — `exemplo.com. 300 IN CAA 0 issue
     * "letsencrypt.org; validationmethods=dns-01"` — então o valor útil está
     * entre aspas e termina no primeiro `;` (o resto são parâmetros).
     * `issue ";"` significa "nenhuma CA autorizada" e não produz domínio algum.
     */
    private Set<String> parseCaaIssueDomains(DnsSecurityResult dns) {
        List<String> records = dns.getCaaRecords();
        if (records == null || records.isEmpty()) {
            // Scans antigos gravados antes de caaRecords existir só têm o singular.
            records = dns.getCaaRecord() == null ? List.of() : List.of(dns.getCaaRecord());
        }

        Set<String> domains = new LinkedHashSet<>();
        for (String record : records) {
            if (record == null) continue;
            String low = record.toLowerCase(Locale.ROOT);
            if (!low.contains("issue")) continue;   // ignora iodef e contactemail

            Matcher m = CAA_VALUE.matcher(low);
            while (m.find()) {
                String value = m.group(1).split(";")[0].trim();
                if (!value.isEmpty()) domains.add(value);
            }
        }
        return domains;
    }

    /**
     * O nome comercial no certificado e o domínio no CAA raramente são a mesma
     * string: "Let's Encrypt" ↔ letsencrypt.org (apóstrofo e espaço),
     * "Google Trust Services" ↔ pki.goog (nada em comum). Compara primeiro pela
     * tabela de aliases e só então cai na aproximação textual, que agora
     * normaliza os dois lados para alfanumérico — sem isso o apóstrofo de
     * "Let's Encrypt" sozinho derrubava a comparação.
     */
    private boolean matchesCa(String issuerLow, String caaDomain) {
        List<String> aliases = CAA_ISSUER_ALIASES.get(caaDomain);
        if (aliases != null && aliases.stream().anyMatch(issuerLow::contains)) return true;

        String issuerNorm = issuerLow.replaceAll("[^a-z0-9]", "");
        String domainNorm = caaDomain.replaceAll("[^a-z0-9]", "");
        if (issuerNorm.length() < 4 || domainNorm.length() < 4) return false;

        return domainNorm.contains(issuerNorm) || issuerNorm.contains(domainNorm);
    }

    private String extractIssuerOrg(String issuerDn) {
        if (issuerDn == null || issuerDn.isBlank()) return "Unknown";
        for (String part : issuerDn.split(",")) {
            part = part.trim();
            if (part.startsWith("o=")) return part.substring(2).trim();
        }
        for (String part : issuerDn.split(",")) {
            part = part.trim();
            if (part.startsWith("cn=")) return part.substring(3).trim();
        }
        return "Unknown";
    }

    private LocalDate parseDate(String dateStr) {
        if (dateStr == null || dateStr.isBlank()) return null;
        try {
            return LocalDateTime.parse(dateStr.replace(" ", "T"),
                    DateTimeFormatter.ISO_LOCAL_DATE_TIME).toLocalDate();
        } catch (DateTimeParseException e1) {
            try { return LocalDate.parse(dateStr.substring(0, 10)); }
            catch (Exception e2) { return null; }
        }
    }

    private CertTransparencyResult emptyResult() {
        return CertTransparencyResult.builder()
                .totalCertificates(0).uniqueSubdomains(0)
                .recentlyIssued(false).wildcardDetected(false).unexpectedIssuer(false)
                .discoveredSubdomains(List.of()).issuers(List.of())
                .unexpectedIssuers(List.of()).wildcardDomains(List.of())
                .recentCerts(List.of()).build();
    }
}