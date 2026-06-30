package com.joao.cyberaudit.service;

/**
 * Constantes HTTP compartilhadas pelos módulos de scan.
 *
 * User-Agent único usado por todos os probes. Formato de bot transparente
 * ("compatible; ...") — passa filtros que exigem prefixo Mozilla e continua
 * identificando o scanner nos logs do site auditado.
 */
public final class ScannerHttp {

    private ScannerHttp() {}

    public static final String USER_AGENT = "Mozilla/5.0 (compatible; CyberAuditScanner/1.0)";
}
