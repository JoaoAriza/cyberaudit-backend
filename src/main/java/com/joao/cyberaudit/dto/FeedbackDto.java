package com.joao.cyberaudit.dto;

import com.joao.cyberaudit.model.Feedback;
import com.joao.cyberaudit.model.FeedbackStatus;
import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;
import java.util.UUID;

/** Representação de leitura de um feedback (cliente e admin). */
@Getter @Builder
public class FeedbackDto {

    private UUID id;
    private UUID scanId;
    private String host;
    private String module;
    private String findingLabel;
    private String message;
    private FeedbackStatus status;
    private String adminResponse;

    private String submittedByName;
    private String submittedByEmail;
    private String reviewedByName;

    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private LocalDateTime resolvedAt;

    /**
     * Mapeia a entidade para DTO. Acessa associações lazy ({@code user},
     * {@code reviewedBy}), portanto deve ser chamado dentro de uma transação /
     * do escopo do Open-Session-In-View.
     */
    public static FeedbackDto from(Feedback f) {
        return FeedbackDto.builder()
                .id(f.getId())
                .scanId(f.getScanId())
                .host(f.getHost())
                .module(f.getModule())
                .findingLabel(f.getFindingLabel())
                .message(f.getMessage())
                .status(f.getStatus())
                .adminResponse(f.getAdminResponse())
                .submittedByName(f.getUser() != null ? f.getUser().getName() : null)
                .submittedByEmail(f.getUser() != null ? f.getUser().getEmail() : null)
                .reviewedByName(f.getReviewedBy() != null ? f.getReviewedBy().getName() : null)
                .createdAt(f.getCreatedAt())
                .updatedAt(f.getUpdatedAt())
                .resolvedAt(f.getResolvedAt())
                .build();
    }
}
