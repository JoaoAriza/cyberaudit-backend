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
     * "HIGH"  — reflexão em Location ou Set-Cookie: vetor explorável
     *           (password-reset/cache poisoning, domain poisoning).
     * "LOW"   — reflexão apenas no body: informativo, geralmente benigno
     *           (canonical/og:url). Não penaliza o score.
     */
    private String severity;
}
