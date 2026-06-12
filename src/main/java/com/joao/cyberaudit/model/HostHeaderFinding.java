package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class HostHeaderFinding {

    /**
     * Header HTTP injetado na requisição.
     * Ex: "Host", "X-Forwarded-Host", "X-Host", "X-Forwarded-Server"
     */
    private String injectedHeader;

    /**
     * Valor injetado no header.
     * Ex: "cyberaudit-probe.invalid"
     */
    private String injectedValue;

    /**
     * Onde o valor injetado foi refletido na resposta:
     * BODY     — refletido no corpo HTML (links, forms, meta tags, text)
     * LOCATION — refletido no header Location (redirect)
     * SET_COOKIE — refletido no domínio do Set-Cookie
     */
    private String reflectionPoint;

    /**
     * Trecho da resposta que confirmou a reflexão (max 150 chars).
     */
    private String evidence;

    /**
     * "HIGH" — reflexão direta pode levar a password-reset poisoning,
     * cache poisoning, open redirect via Host, SSRF via Host.
     */
    private String severity;
}
