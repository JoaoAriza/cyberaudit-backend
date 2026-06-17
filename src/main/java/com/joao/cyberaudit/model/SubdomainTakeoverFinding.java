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
public class SubdomainTakeoverFinding {

    private String subdomain;     // staging.victim.com
    private String cnameTarget;   // unclaimed.github.io
    private String service;       // "GitHub Pages"
    private String vulnerability; // descrição da vulnerabilidade
    private String evidence;      // trecho do body que confirmou
    private String severity;      // CRITICAL, HIGH, MEDIUM
    private String status;        // VULNERABLE, POTENTIAL
}