package com.joao.cyberaudit.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "scheduled_scans")
@Data @Builder @NoArgsConstructor @AllArgsConstructor
public class ScheduledScan {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /** Domínio alvo — sem protocolo (ex: example.com) */
    @Column(nullable = false)
    private String host;

    /** Usar scan ativo (requer ownership verification) */
    @Column(nullable = false)
    private boolean active;

    /** DAILY / WEEKLY */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Frequency frequency;

    /** Horário preferencial de execução (hora do dia, 0-23, UTC) */
    @Column(nullable = false)
    private int preferredHour;

    /** Próxima execução agendada */
    @Column
    private LocalDateTime nextRun;

    /** Última execução concluída */
    @Column
    private LocalDateTime lastRun;

    /** false = pausado (não executa até reativar) */
    @Column(nullable = false)
    private boolean enabled;

    /** Notificar por email ao concluir */
    @Column(nullable = false)
    private boolean notifyEmail;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private AppUser user;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    public enum Frequency { DAILY, WEEKLY }
}
