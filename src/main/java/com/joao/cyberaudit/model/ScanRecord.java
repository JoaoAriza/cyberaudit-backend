package com.joao.cyberaudit.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "scan_records", indexes = {
        @Index(name = "idx_scan_host", columnList = "host"),
        @Index(name = "idx_scan_scanned_at", columnList = "scanned_at")
})
@Getter @Setter @Builder @NoArgsConstructor @AllArgsConstructor
public class ScanRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false)
    private String url;

    @Column(nullable = false)
    private String host;

    @Column(name = "scanned_at", nullable = false)
    private LocalDateTime scannedAt;

    private boolean activeMode;

    private int score;

    @Enumerated(EnumType.STRING)
    private RiskLevel riskLevel;

    /**
     * Rótulo de impacto da página, copiado do laudo para a listagem não precisar
     * abrir o {@code result_json}.
     *
     * Nulo nos scans gravados antes da coluna — e continua nulo: a tela mostra "sem
     * rótulo" em vez de afirmar VITRINE sobre um laudo que não mediu formulário.
     *
     * {@code columnDefinition} explícito para o Hibernate não gerar CHECK com a
     * lista do enum, que o {@code ddl-auto} nunca atualiza (ver audit_logs.action).
     */
    @Enumerated(EnumType.STRING)
    @Column(columnDefinition = "VARCHAR(20)")
    private ImpactLevel impact;

    @Column(columnDefinition = "TEXT", nullable = false)
    private String resultJson;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "account_id")
    private Account account;

    /** Origem do scan: MANUAL (via Scanner UI) ou SCHEDULED (agendamento automático). */
    @Enumerated(EnumType.STRING)
    @Column(columnDefinition = "VARCHAR(20) DEFAULT 'MANUAL'")
    @Builder.Default
    private ScanOrigin origin = ScanOrigin.MANUAL;
}
