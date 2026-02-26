package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class PortFinding {
    private String impact;
    private String recommendation;
    private int port;
    private String service;
    private String state;
    private String severity;
    private Long latencyMs;
    private String evidence;
}

