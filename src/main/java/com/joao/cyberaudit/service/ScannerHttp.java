package com.joao.cyberaudit.service;

/**
 * Constantes HTTP compartilhadas pelos módulos de scan.
 *
 * User-Agent ÚNICO para todos os probes. Antes, os módulos misturavam
 * "CyberAuditScanner/1.0" (sem prefixo Mozilla) e "Mozilla/5.0 CyberAuditScanner/1.0":
 * vários WAFs/bot-filters bloqueiam o UA sem prefixo Mozilla, então módulos diferentes
 * viam respostas diferentes do MESMO site — uns bloqueados (sem achado, parecia "seguro"),
 * outros não. Padronizar elimina essa incoerência entre módulos.
 *
 * Formato de bot transparente ("compatible; ...") — passa filtros que exigem prefixo
 * Mozilla, mas continua identificando o scanner nos logs do site auditado.
 */
public final class ScannerHttp {

    private ScannerHttp() {}

    public static final String USER_AGENT = "Mozilla/5.0 (compatible; CyberAuditScanner/1.0)";
}
