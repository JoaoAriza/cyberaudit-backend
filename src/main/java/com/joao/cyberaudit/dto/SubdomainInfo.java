package com.joao.cyberaudit.dto;

/**
 * Resultado de um subdomínio descoberto via Certificate Transparency + DNS probe.
 */
public record SubdomainInfo(
        String  host,
        boolean alive,
        Integer httpStatus,
        String  ip
) {}
