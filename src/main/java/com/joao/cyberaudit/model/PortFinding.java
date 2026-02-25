package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class PortFinding {
    private int port;
    private String service;     // ex: HTTP, HTTPS, FTP, MySQL...
    private String state;       // OPEN | CLOSED | FILTERED
    private String severity;    // INFO | LOW | MEDIUM | HIGH
    private Long latencyMs;     // tempo de resposta do connect
    private String evidence;    // ex: "HTTP Server: nginx", "FTP banner: ..."
}