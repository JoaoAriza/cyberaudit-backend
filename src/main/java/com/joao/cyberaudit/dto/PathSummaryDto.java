package com.joao.cyberaudit.dto;

import com.joao.cyberaudit.model.RiskLevel;
import com.joao.cyberaudit.model.ScanOrigin;
import com.joao.cyberaudit.model.ScanSummary;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Um caminho scaneado dentro de um domínio, com o score do scan mais recente dele.
 *
 * Existe porque o histórico agrupa por HOST: escanear {@code site.com/login} e
 * {@code site.com} caía na mesma série, misturando páginas diferentes numa única
 * linha de tendência. O caminho sempre esteve gravado em {@code ScanRecord.url};
 * o que faltava era alguém separá-lo.
 *
 * O {@code path} vem pronto do servidor, e não derivado na tela, para a regra de
 * normalização (barra final, ausência de caminho) existir num lugar só.
 */
public record PathSummaryDto(
        UUID id,
        String host,
        String path,
        String url,
        LocalDateTime scannedAt,
        boolean activeMode,
        int score,
        RiskLevel riskLevel,
        ScanOrigin origin
) {
    public static PathSummaryDto from(ScanSummary s, String path) {
        return new PathSummaryDto(s.getId(), s.getHost(), path, s.getUrl(),
                s.getScannedAt(), s.isActiveMode(), s.getScore(), s.getRiskLevel(), s.getOrigin());
    }
}
