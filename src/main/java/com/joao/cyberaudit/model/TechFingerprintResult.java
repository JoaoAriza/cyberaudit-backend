package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;
import java.util.Map;

@Getter @Setter @Builder @NoArgsConstructor @AllArgsConstructor
public class TechFingerprintResult {

    private String       webServer;
    private String       backend;
    private String       framework;
    private String       cms;
    private String       cdn;
    private String       language;
    private List<String> libraries;
    private List<String> evidence;
    private Map<String, String> detectedVersions;
}
