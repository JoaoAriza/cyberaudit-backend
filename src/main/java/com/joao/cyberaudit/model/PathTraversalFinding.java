package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NoArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PathTraversalFinding {

    /**
     * Nome do parametro vulneravel na query string.
     * Ex: "file", "page", "path", "template"
     */
    private String parameter;

    /**
     * Payload que disparou a deteccao.
     * Ex: "../../../etc/passwd"
     */
    private String payload;

    /**
     * Arquivo alvo cujo conteudo foi confirmado na resposta.
     * Ex: "/etc/passwd", "/etc/hosts", "windows/win.ini"
     */
    private String target;

    /**
     * Trecho da resposta que confirmou o vazamento (max 120 chars).
     * Suficiente para evidenciar o problema sem expor dados em excesso.
     */
    private String evidence;

    /**
     * "CRITICAL" — conteudo de arquivo do sistema confirmado na resposta.
     */
    private String severity;
}
