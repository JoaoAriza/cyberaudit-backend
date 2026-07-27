package com.joao.cyberaudit.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Contestação de um cliente sobre um resultado de scan ("isso está errado?").
 *
 * Granularidade por-finding com fallback: o feedback sempre referencia o scan
 * ({@link #scanId} + {@link #host}) e, opcionalmente, o {@link #module} e o
 * {@link #findingLabel} contestados. Se ambos forem nulos, é uma contestação do
 * scan inteiro. Alimenta a triagem do admin e vira dado real de falso-positivo.
 */
@Entity
@Table(name = "feedbacks", indexes = {
        @Index(name = "idx_feedback_status", columnList = "status"),
        @Index(name = "idx_feedback_account", columnList = "account_id"),
        @Index(name = "idx_feedback_created_at", columnList = "created_at")
})
@Getter @Setter @Builder @NoArgsConstructor @AllArgsConstructor
public class Feedback {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /** Scan contestado. Nullable — um scan ao vivo pode não estar persistido. */
    @Column(name = "scan_id")
    private UUID scanId;

    /** Host/domínio do scan — denormalizado para o admin identificar de imediato. */
    @Column(nullable = false)
    private String host;

    /** Módulo contestado (ex: "TLS", "Headers", "CVE"). Null = scan inteiro. */
    private String module;

    /** Rótulo do finding específico contestado (título/id). Null = módulo/scan inteiro. */
    @Column(name = "finding_label")
    private String findingLabel;

    /** Motivo escrito pelo cliente. */
    @Column(columnDefinition = "TEXT", nullable = false)
    private String message;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    @Builder.Default
    private FeedbackStatus status = FeedbackStatus.OPEN;

    /** Resposta do admin durante a triagem. */
    @Column(name = "admin_response", columnDefinition = "TEXT")
    private String adminResponse;

    /** Quem enviou o feedback. */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private AppUser user;

    /** Conta do remetente — usada para escopar a triagem do admin (multi-tenant). */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "account_id")
    private Account account;

    /** Admin que fez a última triagem. */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "reviewed_by")
    private AppUser reviewedBy;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @Column(name = "resolved_at")
    private LocalDateTime resolvedAt;
}
