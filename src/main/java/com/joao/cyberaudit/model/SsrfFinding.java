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
public class SsrfFinding {

    /**
     * Nome do parametro vulneravel na query string.
     * Ex: "url", "callback", "redirect", "webhook"
     */
    private String parameter;

    /**
     * Payload injetado que disparou a deteccao.
     * Ex: "http://169.254.169.254/latest/meta-data/"
     */
    private String payload;

    /**
     * Tipo de indicador que confirmou o SSRF:
     * AWS_METADATA    — conteudo do endpoint de metadata AWS apareceu na resposta
     * GCP_METADATA    — conteudo do endpoint de metadata GCP apareceu na resposta
     * ERROR_DISCLOSURE — erro do servidor revela tentativa de conexao interna
     * INTERNAL_REDIRECT — Location header aponta para endereco interno
     */
    private String indicator;

    /**
     * Trecho da resposta que confirmou o SSRF (max 150 chars).
     */
    private String evidence;

    /**
     * "CRITICAL" — acesso a infraestrutura interna confirmado.
     */
    private String severity;
}
