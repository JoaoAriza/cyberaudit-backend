package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NoArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CertTransparencyResult {

    private int    totalCertificates;        // total de certs encontrados nos logs CT
    private int    uniqueSubdomains;         // subdomínios únicos descobertos
    private String mostRecentIssuance;       // data do cert mais recente (ISO)
    private String oldestIssuance;           // data do cert mais antigo (ISO)
    private boolean recentlyIssued;          // cert emitido nos últimos 7 dias
    private boolean wildcardDetected;        // *.exemplo.com detectado
    private boolean unexpectedIssuer;        // issuer não está na CAA do DNS

    private List<String> discoveredSubdomains;   // subdomínios históricos do CT
    private List<String> issuers;                // CAs que emitiram certs
    private List<String> unexpectedIssuers;      // issuers que violam CAA
    private List<String> wildcardDomains;        // certs wildcard encontrados
    private List<CertEntry> recentCerts;         // certs emitidos nos últimos 30 dias

    @Getter @Setter
@Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class CertEntry {
        private String commonName;
        private String issuer;
        private String notBefore;
        private String notAfter;
        private boolean wildcard;
        private String loggedAt;
    }
}