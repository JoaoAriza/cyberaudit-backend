package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
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

