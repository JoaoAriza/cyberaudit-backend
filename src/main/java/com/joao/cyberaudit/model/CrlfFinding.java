package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CrlfFinding {

    /**
     * Nome do parâmetro vulnerável na query string.
     * Ex: "redirect", "url", "lang", "page"
     */
    private String parameter;

    /**
     * Payload injetado que disparou a detecção.
     * Ex: "%0d%0aX-CyberAudit-Injected:%20crlf-confirmed"
     */
    private String payload;

    /**
     * Tipo de injeção confirmada:
     * CRLF_HEADER   — header injetado apareceu na resposta HTTP (\\r\\n)
     * LF_HEADER     — header injetado via LF somente (\\n)
     * DOUBLE_ENCODE — injeção via %250d%250a (double URL encoding)
     */
    private String injectionType;

    /**
     * Header injetado que apareceu na resposta.
     * Ex: "X-CyberAudit-Injected: crlf-probe-7x3k"
     */
    private String evidence;

    /**
     * "HIGH" — response splitting / header injection permite injetar
     * Set-Cookie arbitrário, XSS via cabeçalho, cache poisoning.
     */
    private String severity;
}
