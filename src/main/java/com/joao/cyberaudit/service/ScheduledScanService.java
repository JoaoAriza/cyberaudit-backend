package com.joao.cyberaudit.service;

import com.joao.cyberaudit.dto.ScheduledScanDto;
import com.joao.cyberaudit.dto.ScheduledScanRequest;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.ScheduledScan;
import com.joao.cyberaudit.model.ScheduledScan.Frequency;
import com.joao.cyberaudit.repository.ScheduledScanRepository;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

@Service
public class ScheduledScanService {

    private final ScheduledScanRepository repo;
    private final ScanOrchestrator        orchestrator;
    private final EmailService            emailService;
    private final PlanLimitService        planLimitService;

    public ScheduledScanService(ScheduledScanRepository repo,
                                ScanOrchestrator orchestrator,
                                EmailService emailService,
                                PlanLimitService planLimitService) {
        this.repo             = repo;
        this.orchestrator     = orchestrator;
        this.emailService     = emailService;
        this.planLimitService = planLimitService;
    }

    // ── CRUD ─────────────────────────────────────────────────────────────────

    @Transactional
    public ScheduledScanDto create(ScheduledScanRequest req, AppUser user) {
        // Verifica se o plano permite mais agendamentos
        int currentCount = repo.findByUserOrderByCreatedAtDesc(user).size();
        planLimitService.checkScheduledScanSlots(user, currentCount);

        Frequency freq = Frequency.valueOf(req.getFrequency().toUpperCase());

        ScheduledScan scan = ScheduledScan.builder()
                .host(sanitizeHost(req.getHost()))
                .active(req.isActive())
                .frequency(freq)
                .preferredHour(Math.max(0, Math.min(23, req.getPreferredHour())))
                .nextRun(calcNextRun(freq, req.getPreferredHour()))
                .enabled(true)
                .notifyEmail(req.isNotifyEmail())
                .user(user)
                .createdAt(LocalDateTime.now())
                .build();

        return ScheduledScanDto.from(repo.save(scan));
    }

    public List<ScheduledScanDto> listByUser(AppUser user) {
        return repo.findByUserOrderByCreatedAtDesc(user)
                .stream().map(ScheduledScanDto::from).toList();
    }

    @Transactional
    public ScheduledScanDto toggleEnabled(UUID id, AppUser user) {
        ScheduledScan scan = getOwned(id, user);
        scan.setEnabled(!scan.isEnabled());
        if (scan.isEnabled() && scan.getNextRun() == null) {
            scan.setNextRun(calcNextRun(scan.getFrequency(), scan.getPreferredHour()));
        }
        return ScheduledScanDto.from(repo.save(scan));
    }

    @Transactional
    public void delete(UUID id, AppUser user) {
        ScheduledScan scan = getOwned(id, user);
        repo.delete(scan);
    }

    // ── Execução automática ───────────────────────────────────────────────────

    /**
     * Roda a cada minuto e dispara os scans cujo nextRun já passou.
     * Execução é síncrona por design — evita sobrecarga de threads paralelas.
     * Para produção com muitos agendamentos, evoluir para fila assíncrona.
     */
    @Scheduled(fixedDelay = 60_000)
    @Transactional
    public void runDueScans() {
        List<ScheduledScan> due = repo.findDue(LocalDateTime.now());
        for (ScheduledScan scan : due) {
            try {
                var result = orchestrator.execute(
                        scan.getHost(), scan.isActive(), scan.getUser(), true);

                scan.setLastRun(LocalDateTime.now());
                scan.setNextRun(calcNextRun(scan.getFrequency(), scan.getPreferredHour()));
                repo.save(scan);

                if (scan.isNotifyEmail()) {
                    emailService.sendScanComplete(
                            scan.getUser().getEmail(),
                            scan.getUser().getName(),
                            result);
                }
            } catch (Exception e) {
                // Não deixa falha de um scan cancelar os demais
                System.err.println("[ScheduledScan] Falha ao executar scan para "
                        + scan.getHost() + ": " + e.getMessage());
                // Avança nextRun para evitar retry imediato infinito
                scan.setNextRun(LocalDateTime.now().plusMinutes(30));
                repo.save(scan);
            }
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private ScheduledScan getOwned(UUID id, AppUser user) {
        return repo.findById(id)
                .filter(s -> s.getUser().getId().equals(user.getId()))
                .orElseThrow(() -> new RuntimeException("Agendamento não encontrado"));
    }

    private LocalDateTime calcNextRun(Frequency freq, int preferredHour) {
        LocalDateTime now  = LocalDateTime.now();
        LocalDateTime next = now.truncatedTo(ChronoUnit.DAYS)
                               .withHour(preferredHour);
        // Se o horário de hoje já passou, empurra para o próximo ciclo
        if (!next.isAfter(now)) {
            next = next.plusDays(freq == Frequency.WEEKLY ? 7 : 1);
        }
        return next;
    }

    private String sanitizeHost(String host) {
        if (host == null) return "";
        return host.replaceFirst("^https?://", "").split("/")[0].trim().toLowerCase();
    }
}
