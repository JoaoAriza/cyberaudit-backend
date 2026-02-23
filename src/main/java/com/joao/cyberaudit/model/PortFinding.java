package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class PortFinding {
    private int port;
    private String service;
    private boolean open;
    private String severity;
    private String impact;
    private String recommendation;
}
