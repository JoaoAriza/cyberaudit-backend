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
        if (dns == null || !dns.isCaaPresent() || dns.getCaaRecord() == null)
            return List.of();

        String caaRecord = dns.getCaaRecord().toLowerCase();
        List<String> unexpected = new ArrayList<>();

        for (String issuer : recentIssuers) {
            String issuerLow = issuer.toLowerCase();
            if (issuerLow.isBlank() || issuerLow.equals("unknown")) continue;

            boolean authorizedByCAA = Arrays.stream(caaRecord.split("[\\s\".,;]+"))
                    .filter(token -> token.length() > 3)
                    .anyMatch(token -> issuerLow.contains(token)
                            || token.contains(issuerLow.replaceAll("\\s+", "")));

            if (!authorizedByCAA) unexpected.add(issuer);
        }
        return unexpected;
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