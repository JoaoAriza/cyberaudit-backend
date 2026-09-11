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

    /**
     * Fuso em que {@code preferredHour} deve ser lido (ex: "America/Sao_Paulo").
     *
     * Fica no agendamento, e não só no usuário, porque a intenção pertence ao
     * agendamento: quem monta a rotina para as 8h do horário de Brasília e depois
     * se muda para Lisboa quer o scan continuando às 8h de Brasília, junto com o
     * time que lê o relatório. Ler o fuso do usuário na hora de executar mudaria
     * o horário de uma rotina existente por causa de uma viagem.
     *
     * Nulo nos agendamentos criados antes desta coluna existir — nesse caso vale
     * UTC, que é como a hora deles foi escolhida e continua sendo exibida.
     */
    @Column(length = 64)
    private String timezone;

    /**
     * Caminho dentro do domínio (ex: {@code /login}). Nulo ou "/" = a raiz.
     *
     * Antes o caminho era descartado na criação — {@code split("/")[0]} reduzia
     * {@code site.com/login} a {@code site.com}, e a rotina passava a monitorar
     * em silêncio uma página diferente da pedida. Guardar separado mantém o
     * {@code host} como a unidade de domínio (plano, e-mail, verificação) e o
     * caminho como o alvo real do scan.
     *
     * Nulo nos agendamentos criados antes desta coluna existir — e nesse caso a
     * raiz é exatamente o que eles já escaneavam.
     */
    @Column(length = 300)
    private String path;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private AppUser user;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    public enum Frequency { DAILY, WEEKLY }
}
