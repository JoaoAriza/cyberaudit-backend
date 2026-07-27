package com.joao.cyberaudit.dto;

import lombok.Getter;
import lombok.Setter;

import java.util.UUID;

/** Payload de submissão de feedback (contestação) pelo cliente. */
@Getter @Setter
public class FeedbackRequest {

    /** Scan contestado (opcional — pode não estar persistido no Scanner ao vivo). */
    private UUID scanId;

    /** Host/domínio do scan (obrigatório). */
    private String host;

    /** Módulo contestado, ex: "TLS", "Headers" (opcional). */
    private String module;

    /** Rótulo do finding específico contestado (opcional). */
    private String findingLabel;

    /** Motivo/descrição do cliente (obrigatório). */
    private String message;
}
