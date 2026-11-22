package com.joao.cyberaudit.exception;

import lombok.Getter;

/**
 * O alvo do scan não existe ou não aceitou conexão: não há o que auditar, então não sai
 * laudo nem nota (BUG-16 do cyberaudit-qa).
 *
 * Antes o scan seguia mesmo assim. Um domínio digitado errado saía com 17/100, CRITICAL
 * (sem SPF nem DMARC num domínio que não existe, o DNS de e-mail ainda descontava), e 14
 * módulos marcavam "OK" sem terem falado com ninguém.
 *
 * Dois casos, decididos pelo dono em 2026-11-22:
 * - {@link #NAO_RESOLVE}: o domínio não resolve no DNS. Recusado antes de gastar cota.
 * - {@link #SEM_RESPOSTA}: resolve, mas nada aceitou a conexão nem em http nem em https.
 *   Só se descobre tentando conectar, então a cota já foi gasta.
 */
@Getter
public class TargetUnreachableException extends RuntimeException {

    public static final String NAO_RESOLVE  = "TARGET_NOT_FOUND";
    public static final String SEM_RESPOSTA = "TARGET_UNREACHABLE";

    /** {@link #NAO_RESOLVE} ou {@link #SEM_RESPOSTA}: vai no campo {@code error} da resposta. */
    private final String codigo;
    private final String host;

    public TargetUnreachableException(String codigo, String host, String message) {
        super(message);
        this.codigo = codigo;
        this.host   = host;
    }
}
