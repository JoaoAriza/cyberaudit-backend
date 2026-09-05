package com.joao.cyberaudit.model;

import lombok.Data;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * A linha do histórico: o que a tela mostra numa lista de scans.
 *
 * O banco chega aqui por dois caminhos — {@link #from(ScanRecord)}, quando a
 * entidade já está carregada, e a projeção JPQL do repositório, que monta este
 * objeto direto no SELECT sem tocar no {@code result_json}. O segundo existe
 * porque o laudo inteiro vive naquela coluna TEXT, e listar 50 scans arrastava 50
 * laudos que a tela descartava.
 */
@Data
public class ScanSummary {
    private UUID id;
    private String url;
    private String host;
    private LocalDateTime scannedAt;
    private boolean activeMode;
    private int score;
    private RiskLevel riskLevel;
    private ScanOrigin origin;

    /**
     * Construtor explícito, e não {@code @AllArgsConstructor}, por causa do
     * {@code origin}: registros gravados antes daquela coluna existir vêm com null.
     * O default mora aqui porque agora são dois caminhos de entrada, e a projeção
     * JPQL não tem onde aplicar o coalesce.
     */
    public ScanSummary(UUID id, String url, String host, LocalDateTime scannedAt,
                       boolean activeMode, int score, RiskLevel riskLevel, ScanOrigin origin) {
        this.id         = id;
        this.url        = url;
        this.host       = host;
        this.scannedAt  = scannedAt;
        this.activeMode = activeMode;
        this.score      = score;
        this.riskLevel  = riskLevel;
        this.origin     = origin != null ? origin : ScanOrigin.MANUAL;
    }

    public static ScanSummary from(ScanRecord record) {
        return new ScanSummary(
                record.getId(),
                record.getUrl(),
                record.getHost(),
                record.getScannedAt(),
                record.isActiveMode(),
                record.getScore(),
                record.getRiskLevel(),
                record.getOrigin()
        );
    }
}