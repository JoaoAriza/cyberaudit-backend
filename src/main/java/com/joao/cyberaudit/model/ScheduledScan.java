package com.joao.cyberaudit.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "scheduled_scans")
@Getter @Setter
@Builder @NoArgsConstructor @AllArgsConstructor
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

    /**
     * Idioma do laudo e do e-mail deste agendamento (ex: "pt-BR", "en").
     *
     * O agendamento é o único caminho que roda sem requisição HTTP, então não há
     * Accept-Language para consultar na hora de executar. Guardar o idioma de
     * quem criou é o que evita o scan agendado sair sempre no padrão.
     *
     * Nulo nos agendamentos criados antes desta coluna existir — nesse caso vale
     * o idioma padrão, que é exatamente o que eles já recebiam.
     */
    @Column(length = 16)
    private String locale;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private AppUser user;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    public enum Frequency { DAILY, WEEKLY }
}
