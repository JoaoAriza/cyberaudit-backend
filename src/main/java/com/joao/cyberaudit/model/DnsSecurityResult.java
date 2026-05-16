package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DnsSecurityResult {

    private boolean spfPresent;
    private String spfRecord;
    private String spfPolicy;

    private boolean dmarcPresent;
    private String  dmarcRecord;
    private String dmarcPolicy;

    private boolean dkimHintFound;
    private String dkimSelector;

    private boolean caaPresent;
    private String caaRecord;

    private boolean mxPresent;
    private java.util.List<String> mxRecords;

    // ── Score e resumo ─────────────────────────────────────────────
    /**
     * Nível de risco de email spoofing:
     * LOW      = SPF strong + DMARC reject
     * MEDIUM   = SPF presente + DMARC weak/ausente
     * HIGH     = SPF ausente ou fraco, sem DMARC
     * CRITICAL = sem SPF e sem DMARC (domínio spoofável livremente)
     */
    private String emailSpoofingRisk;

    private String summary;
}