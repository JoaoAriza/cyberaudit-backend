package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.*;
import com.joao.cyberaudit.repository.AppUserRepository;
import com.joao.cyberaudit.repository.ScanRecordRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Detecta degradação de score entre o scan atual e o anterior e envia
 * notificação por email ao OWNER (e ADMIN) da conta afetada.
 *
 * Critérios configuráveis via application.properties:
 *   notification.degradation.score-drop-threshold  (default: 10)
 *     Score caiu >= N pontos.
 *   notification.degradation.notify-on-new-critical (default: true)
 *     Qualquer issue CRITICAL nova → notifica independente do threshold.
 *
 * Nunca propaga exceções — é fire-and-forget.
 */
@Service
public class DegradationNotificationService {

    @Value("${notification.degradation.score-drop-threshold:10}")
    private int scoreDropThreshold;

    @Value("${notification.degradation.notify-on-new-critical:true}")
    private boolean notifyOnNewCritical;

    private final ScanRecordRepository scanRecordRepository;
    private final AppUserRepository    appUserRepository;
    private final EmailService         emailService;

    public DegradationNotificationService(ScanRecordRepository scanRecordRepository,
                                          AppUserRepository appUserRepository,
                                          EmailService emailService) {
        this.scanRecordRepository = scanRecordRepository;
        this.appUserRepository    = appUserRepository;
        this.emailService         = emailService;
    }

    /**
     * Chama após salvar um novo ScanResult. Compara com o scan anterior do
     * mesmo host. Se houver degradação significativa, envia email ao OWNER.
     *
     * @param currentResult  resultado recém-salvo
     * @param account        conta proprietária (null = usuário anônimo, sem notificação)
     */
    public void checkAndNotify(ScanResult currentResult, Account account) {
        if (account == null) return;
        try {
            String host = extractHost(currentResult);
            if (host == null) return;

            // Busca os 2 scans mais recentes do host (o atual e o anterior)
            List<ScanRecord> recent = scanRecordRepository
                    .findByHostOrderByScannedAtDesc(host, PageRequest.of(0, 2));

            if (recent.size() < 2) return; // sem histórico, sem comparação

            ScanRecord current  = recent.get(0);
            ScanRecord previous = recent.get(1);

            int currentScore  = current.getScore();
            int previousScore = previous.getScore();
            int drop          = previousScore - currentScore;

            boolean scoreDegraded  = drop >= scoreDropThreshold;
            boolean newCritical    = notifyOnNewCritical && hasNewCritical(currentResult);
            boolean riskWorsened   = riskWorsened(previous.getRiskLevel(), current.getRiskLevel());

            if (!scoreDegraded && !newCritical && !riskWorsened) return;

            // Notifica OWNER (e ADMIN) da conta
            List<AppUser> owners = appUserRepository.findByAccountAndRole(account, Role.OWNER);
            List<AppUser> admins = appUserRepository.findByAccountAndRole(account, Role.ADMIN);

            String reason = buildReason(drop, scoreDegraded, newCritical, riskWorsened,
                    previous.getRiskLevel(), current.getRiskLevel());

            for (AppUser recipient : concat(owners, admins)) {
                if (!recipient.isActive()) continue;
                emailService.sendDegradationAlert(
                        recipient.getEmail(),
                        recipient.getName(),
                        host,
                        previousScore,
                        currentScore,
                        current.getRiskLevel() != null ? current.getRiskLevel().name() : "UNKNOWN",
                        reason,
                        currentResult
                );
            }
        } catch (Exception e) {
            System.err.println("[DegradationNotification] Erro: " + e.getMessage());
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private String extractHost(ScanResult r) {
        String url = r.getFinalUrl() != null ? r.getFinalUrl() : r.getUrl();
        if (url == null) return null;
        try {
            return new java.net.URI(url.startsWith("http") ? url : "https://" + url)
                    .getHost();
        } catch (Exception e) {
            return null;
        }
    }

    private boolean hasNewCritical(ScanResult result) {
        if (result.getScore() == null || result.getScore().getIssues() == null) return false;
        return result.getScore().getIssues().stream()
                .anyMatch(i -> "CRITICAL".equals(i.getSeverity()));
    }

    private boolean riskWorsened(RiskLevel previous, RiskLevel current) {
        if (previous == null || current == null) return false;
        return riskOrdinal(current) > riskOrdinal(previous);
    }

    private int riskOrdinal(RiskLevel r) {
        return switch (r) {
            case SECURE  -> 0;
            case LOW     -> 1;
            case MEDIUM, WARNING -> 2;
            case HIGH    -> 3;
            case CRITICAL -> 4;
        };
    }

    private String buildReason(int drop, boolean scoreDegraded, boolean newCritical,
                               boolean riskWorsened, RiskLevel oldRisk, RiskLevel newRisk) {
        StringBuilder sb = new StringBuilder();
        if (scoreDegraded)  sb.append("Score caiu ").append(drop).append(" pontos. ");
        if (newCritical)    sb.append("Novo(s) issue(s) CRITICAL detectado(s). ");
        if (riskWorsened)   sb.append("Nível de risco: ")
                              .append(oldRisk).append(" → ").append(newRisk).append(". ");
        return sb.toString().trim();
    }

    @SafeVarargs
    private static <T> List<T> concat(List<T>... lists) {
        return java.util.Arrays.stream(lists)
                .flatMap(List::stream)
                .toList();
    }
}
