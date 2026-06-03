package com.joao.cyberaudit.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.joao.cyberaudit.model.CertTransparencyResult;
import com.joao.cyberaudit.model.DnsSecurityResult;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class CertTransparencyService {

    private static final String CRT_SH_API   = "https://crt.sh/?q=%s&output=json";
    private static final int    MAX_CERTS     = 200;   // limite de certs a processar
    private static final int    MAX_SUBDOMS   = 100;   // limite de subdomínios únicos
    private static final int    RECENT_DAYS   = 7;     // janela para "recém emitido"
    private static final int    DISPLAY_DAYS  = 30;    // janela para exibir no card

    // CAs legítimas e comuns — issuers fora desta lista + sem CAA = suspeito
    private static final Set<String> KNOWN_CAS = Set.of(
            "let's encrypt", "letsencrypt",
            "digicert", "digicert inc",
            "comodo", "sectigo",
            "globalsign", "global sign",
            "entrust", "entrust datacard",
            "godaddy", "go daddy",
            "geotrust", "rapidssl",
            "thawte", "verisign",
            "amazon", "amazon root ca",
            "microsoft", "apple",
            "google trust services", "google",
            "zerossl",
            "cloudflare", "cloudflare inc's",
            "buypass", "certum",
            "trustwave", "ssl.com",
            "harica", "pki"
    );

    private final HttpClient   client  = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10)).build();
    private final ObjectMapper jackson = new ObjectMapper();

    /**
     * Consulta o crt.sh e analisa o histórico de certificados do domínio.
     *
     * @param host              domínio alvo (ex: "github.com")
     * @param dnsSecurityResult resultado DNS já calculado — usado para cross-check com CAA
     */
    public CertTransparencyResult scan(String host, DnsSecurityResult dnsSecurityResult) {
        if (host == null || host.isBlank()) return emptyResult();

        List<JsonNode> rawCerts = fetchCerts(host);
        if (rawCerts.isEmpty()) return emptyResult();

        // ── Processa cada certificado ─────────────────────────────────────────
        Set<String>  subdomains         = new LinkedHashSet<>();
        Set<String>  issuers            = new LinkedHashSet<>();
        Set<String>  wildcardDomains    = new LinkedHashSet<>();
        List<CertTransparencyResult.CertEntry> recentCerts = new ArrayList<>();

        String mostRecent = null;
        String oldest     = null;
        boolean recentlyIssued   = false;
        boolean wildcardDetected = false;

        LocalDate cutoff    = LocalDate.now().minusDays(DISPLAY_DAYS);
        LocalDate recentCut = LocalDate.now().minusDays(RECENT_DAYS);

        for (JsonNode cert : rawCerts) {
            String nameValue  = cert.path("name_value").asText("");
            String issuerName = cert.path("issuer_name").asText("").toLowerCase();
            String notBefore  = cert.path("not_before").asText("");
            String notAfter   = cert.path("not_after").asText("");
            String loggedAt   = cert.path("entry_timestamp").asText(notBefore);

            // Subdomínios descobertos
            for (String name : nameValue.split("[\\n,]")) {
                name = name.trim().toLowerCase();
                if (name.isEmpty() || name.equals(host)) continue;

                if (name.startsWith("*.")) {
                    wildcardDetected = true;
                    wildcardDomains.add(name);
                    name = name.substring(2); // remove *. para adicionar o domínio base
                }

                if (name.endsWith("." + host) || name.equals(host)) {
                    if (subdomains.size() < MAX_SUBDOMS) subdomains.add(name);
                }
            }

            // Issuers
            String issuerClean = extractIssuerOrg(issuerName);
            if (!issuerClean.isBlank()) issuers.add(issuerClean);

            // Datas
            if (!notBefore.isBlank()) {
                if (mostRecent == null || notBefore.compareTo(mostRecent) > 0) mostRecent = notBefore;
                if (oldest    == null || notBefore.compareTo(oldest)     < 0) oldest     = notBefore;
            }

            // Cert recém emitido
            LocalDate issueDate = parseDate(notBefore);
            if (issueDate != null) {
                if (!issueDate.isBefore(recentCut)) recentlyIssued = true;

                // Adiciona ao card de certs recentes
                if (!issueDate.isBefore(cutoff) && recentCerts.size() < 10) {
                    boolean isCertWildcard = nameValue.contains("*.");
                    recentCerts.add(CertTransparencyResult.CertEntry.builder()
                            .commonName(cert.path("common_name").asText(nameValue.split("[\\n,]")[0]))
                            .issuer(extractIssuerOrg(issuerName))
                            .notBefore(notBefore.split("T")[0])
                            .notAfter(notAfter.split("T")[0])
                            .wildcard(isCertWildcard)
                            .loggedAt(loggedAt.split("T")[0])
                            .build());
                }
            }
        }

        // ── Cross-check: issuers vs CAA ────────────────────────────────────────
        List<String> unexpectedIssuers = detectUnexpectedIssuers(
                issuers, dnsSecurityResult);

        // ── Subdomínios históricos (remove o host base) ───────────────────────
        List<String> discoveredSubdomains = subdomains.stream()
                .filter(s -> !s.equals(host))
                .sorted()
                .limit(MAX_SUBDOMS)
                .collect(Collectors.toList());

        // Ordena recentes por data desc
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
                .issuers(new ArrayList<>(issuers))
                .unexpectedIssuers(unexpectedIssuers)
                .wildcardDomains(new ArrayList<>(wildcardDomains))
                .recentCerts(recentCerts)
                .build();
    }

    // ── Private ───────────────────────────────────────────────────────────────

    private List<JsonNode> fetchCerts(String host) {
        try {
            String url = String.format(CRT_SH_API, "%25." + host);
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .GET()
                    .timeout(Duration.ofSeconds(15))
                    .header("User-Agent", "CyberAuditScanner/1.0")
                    .header("Accept", "application/json")
                    .build();

            HttpResponse<String> resp = client.send(req,
                    HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) return List.of();

            JsonNode root = jackson.readTree(resp.body());
            if (!root.isArray()) return List.of();

            List<JsonNode> certs = new ArrayList<>();
            for (JsonNode cert : root) {
                certs.add(cert);
                if (certs.size() >= MAX_CERTS) break;
            }
            return certs;
        } catch (Exception e) {
            return List.of();
        }
    }

    /**
     * Extrai o nome da organização do issuer_name (campo DN).
     * Ex: "C=US, O=Let's Encrypt, CN=R3" → "Let's Encrypt"
     */
    private String extractIssuerOrg(String issuerDn) {
        if (issuerDn == null || issuerDn.isBlank()) return "Unknown";
        for (String part : issuerDn.split(",")) {
            part = part.trim();
            if (part.startsWith("o=")) {
                return part.substring(2).trim();
            }
        }
        // fallback: usa o CN
        for (String part : issuerDn.split(",")) {
            part = part.trim();
            if (part.startsWith("cn=")) {
                return part.substring(3).trim();
            }
        }
        return "Unknown";
    }

    /**
     * Detecta issuers que não estão autorizados pelo CAA record.
     * Só flagga se o domínio tem CAA configurado (senão não há restrição).
     */
    private List<String> detectUnexpectedIssuers(Set<String> issuers,
                                                 DnsSecurityResult dns) {
        if (dns == null || !dns.isCaaPresent() || dns.getCaaRecord() == null)
            return List.of(); // sem CAA = qualquer issuer é válido

        String caaRecord = dns.getCaaRecord().toLowerCase();
        List<String> unexpected = new ArrayList<>();

        for (String issuer : issuers) {
            String issuerLow = issuer.toLowerCase();
            // Verifica se o issuer aparece (mesmo parcialmente) no CAA record
            boolean authorizedByCAA = KNOWN_CAS.stream()
                    .anyMatch(ca -> issuerLow.contains(ca))
                    && caaRecord.contains(issuerLow.split(" ")[0]);

            if (!authorizedByCAA && !issuerLow.isBlank() && !issuerLow.equals("unknown")) {
                // Verifica se algum token do CAA record aparece no nome do issuer
                boolean inCaa = Arrays.stream(caaRecord.split("[\\s\"]+"))
                        .filter(t -> t.length() > 3)
                        .anyMatch(token -> issuerLow.contains(token) || token.contains(issuerLow.split(" ")[0]));
                if (!inCaa) unexpected.add(issuer);
            }
        }
        return unexpected;
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
                .unexpectedIssuers(List.of()).wildcardDomains(List.of()).recentCerts(List.of())
                .build();
    }
}