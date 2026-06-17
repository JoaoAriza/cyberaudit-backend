package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter @Setter @Builder @NoArgsConstructor @AllArgsConstructor
public class DnsSecurityResult {

    private boolean spfPresent;
    private String spfRecord;
    private String spfPolicy;

    private boolean dmarcPresent;
    private String  dmarcRecord;
    private String  dmarcPolicy;

    private boolean dkimHintFound;
    private String  dkimSelector;

    private boolean caaPresent;
    private String  caaRecord;

    private boolean mxPresent;
    private List<String> mxRecords;

    private String emailSpoofingRisk;
    private String summary;
}
