package com.joao.cyberaudit.dto;

import com.joao.cyberaudit.model.FeedbackStatus;
import lombok.Getter;
import lombok.Setter;

/** Payload da triagem do admin: resposta e/ou mudança de status. */
@Getter @Setter
public class FeedbackReplyRequest {

    /** Resposta do admin ao cliente (opcional). */
    private String adminResponse;

    /** Novo status: OPEN | REVIEWING | RESOLVED (opcional). */
    private FeedbackStatus status;
}
