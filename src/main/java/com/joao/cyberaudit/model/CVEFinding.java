package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NoArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CVEFinding {

    private String cveId;            // CVE-2021-41773
    private String severity;         // CRITICAL, HIGH, MEDIUM, LOW
    private double cvssScore;        // 9.8
    private String description;      // resumo da vulnerabilidade
    private String affectedSoftware; // "Apache HTTP Server 2.4.49"
    private String publishedDate;    // "2021-10-05"
    private String referenceUrl;     // https://nvd.nist.gov/vuln/detail/CVE-...
}