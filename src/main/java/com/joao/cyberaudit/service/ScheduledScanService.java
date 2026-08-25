package com.joao.cyberaudit.service;

import com.joao.cyberaudit.config.LocaleConfig;
import com.joao.cyberaudit.dto.ScheduledScanDto;
import com.joao.cyberaudit.dto.ScheduledScanRequest;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.ScanOrigin;
import com.joao.cyberaudit.model.ScheduledScan;
import com.joao.cyberaudit.model.ScheduledScan.Frequency;
import com.joao.cyberaudit.repository.ScheduledScanRepository;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

@Service
public class ScheduledScanService {

    private final ScheduledScanRepository  repo;
    private final ScanOrchestrator         orchestrator;
    private final EmailService             emailService;
    private final PlanLimitService         planLimitService;
    private final ScanEntitlementService   scanEntitlement;

    public ScheduledScanService(ScheduledScanRepository repo,
                                ScanOrchestrator orchestrator,
                                EmailService emailService,
                                PlanLimitService planLimitService,
                                ScanEntitlementService scanEntitlement) {
        this.repo             = repo;
        this.orchestrator     = orchestrator;
        this.emailService     = emailService;
        this.planLimitService = planLimitService;
        this.scanEntitlement  = scanEntitlement;
    }

    // ── CRUD ─────────────────────────────────────────────────────────────────

    @Transactional
    public ScheduledScanDto create(ScheduledScanRequest req, AppUser user) {
        // Verifica se o plano permite mais agendamentos
        int currentCount = repo.findByUserOrderByCreatedAtDesc(user).size();
        planLimitService.checkScheduledScanSlots(user, currentCount);
        // Agendar já é PRO+, mas notificar por e-mail carrega a regra de domínio:
        // o Pro pessoal só recebe laudo do que é dele.
        if (req.isNotifyEmail()) {
            planLimitService.checkEmailNotify(user, req.getHost());
        }

        Frequency freq = Frequency.valueOf(req.getFrequency().toUpperCase());

        ScheduledScan scan = ScheduledScan.builder()
                .host(sanitizeHost(req.getHost()))
                .active(req.isActive())
                .frequency(freq)
                .preferredHour(Math.max(0, Math.min(23, req.getPreferredHour())))
                .nextRun(calcNextRun(freq, req.getPreferredHour()))
                .enabled(true)
                .notifyEmail(req.isNotifyEmail())
                // Capturado aqui porque a execução roda fora de requisição.
                .locale(LocaleContextHolder.getLocale().toLanguageTag())
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
     *
     * NÃO é @Transactional: scans HTTP podem durar minutos; manter uma transação
     * aberta por todo esse tempo esgota o pool de conexões. A busca inicial e
     * os saves pontuais são feitos via métodos @Transactional auxiliares.
     */
    @Scheduled(fixedDelay = 60_000)
    public void runDueScans() {
        // Carrega scans devidos em transação curta (JOIN FETCH user+account)
        List<ScheduledScan> due = loadDueScans();
        for (ScheduledScan scan : due) {
            try {
                // Idioma de quem criou o agendamento. Vale para o laudo e para o
                // e-mail; sem isto, os dois sairiam no padrão. O finally limpa: a
                // thread do agendador é a mesma para todos os scans da rodada.
                LocaleContextHolder.setLocale(idiomaDe(scan));

                // Executa scan fora de qualquer transação — pode durar longos segundos
                var result = orchestrator.execute(
                        scan.getHost(), scan.isActive(), scan.getUser(), true, ScanOrigin.SCHEDULED);

                // Persiste nextRun e lastRun em transação curta separada
                markSuccess(scan.getId(), calcNextRun(scan.getFrequency(), scan.getPreferredHour()));

                // Reconfere o plano na hora de enviar: entre a criação do agendamento
                // e esta rodada a assinatura pode ter caído. Variante que não lança —
                // exceção aqui mataria as demais notificações da rodada.
                if (scan.isNotifyEmail()
                        && planLimitService.canEmailNotify(scan.getUser(), scan.getHost())) {
                    // Mesmo gating da tela: o e-mail é canal de entrega, não atalho
                    // para o resultado cru.
                    emailService.sendScanComplete(
                            scan.getUser().getEmail(),
                            scan.getUser().getName(),
                            scanEntitlement.applyEntitlement(result, scan.getUser()));
                }
            } catch (Exception e) {
                // Não deixa falha de um scan cancelar os demais
                System.err.println("[ScheduledScan] Falha ao executar scan para "
                        + scan.getHost() + ": " + e.getMessage());
                // Avança nextRun para evitar retry imediato infinito
                markRetry(scan.getId());
            } finally {
                LocaleContextHolder.resetLocaleContext();
            }
        }
    }

    /**
     * Idioma do agendamento. Agendamento criado antes da coluna existir tem locale
     * nulo e cai no padrão — que é o que ele já recebia.
     */
    private static Locale idiomaDe(ScheduledScan scan) {
        String tag = scan.getLocale();
        return tag == null || tag.isBlank() ? LocaleConfig.PADRAO : Locale.forLanguageTag(tag);
    }

    @Transactional(readOnly = true)
    public List<ScheduledScan> loadDueScans() {
        return repo.findDue(LocalDateTime.now());
    }

    @Transactional
    public void markSuccess(UUID id, LocalDateTime nextRun) {
        repo.findById(id).ifPresent(s -> {
            s.setLastRun(LocalDateTime.now());
            s.setNextRun(nextRun);
            repo.save(s);
        });
    }

    @Transactional
    public void markRetry(UUID id) {
        repo.findById(id).ifPresent(s -> {
            s.setNextRun(LocalDateTime.now().plusMinutes(30));
            repo.save(s);
        });
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
