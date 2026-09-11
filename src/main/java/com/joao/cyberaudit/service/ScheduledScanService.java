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
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
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
    private final UserTimeZoneService      userTimeZone;

    public ScheduledScanService(ScheduledScanRepository repo,
                                ScanOrchestrator orchestrator,
                                EmailService emailService,
                                PlanLimitService planLimitService,
                                ScanEntitlementService scanEntitlement,
                                UserTimeZoneService userTimeZone) {
        this.repo             = repo;
        this.orchestrator     = orchestrator;
        this.emailService     = emailService;
        this.planLimitService = planLimitService;
        this.scanEntitlement  = scanEntitlement;
        this.userTimeZone     = userTimeZone;
    }

    // ── CRUD ─────────────────────────────────────────────────────────────────

    @Transactional
    public ScheduledScanDto create(ScheduledScanRequest req, AppUser user) {
        // Verifica se o plano permite mais agendamentos
        List<ScheduledScan> existentes = repo.findByUserOrderByCreatedAtDesc(user);
        planLimitService.checkScheduledScanSlots(user, existentes.size());

        // Host e caminho saem do mesmo campo: a tela manda a URL inteira.
        String hostNovo = sanitizeHost(req.getHost());
        String pathNovo = ScanHistoryService.normalizarCaminho(caminhoPedido(req));

        // A mesma página duas vezes na lista só duplica o scan e o e-mail. Frequência
        // não conta: diário e semanal do mesmo endereço é o diário com um extra.
        if (existentes.stream().anyMatch(s -> mesmaFamilia(s.getHost(), hostNovo)
                && ScanHistoryService.normalizarCaminho(s.getPath()).equals(pathNovo))) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Este endereço já tem um agendamento. Pause ou remova o atual para mudar a frequência.");
        }

        // Agendar já é PRO+, mas notificar por e-mail carrega a regra de domínio:
        // o Pro pessoal só recebe laudo do que é dele. Host já limpo — com o
        // caminho grudado, "site.com/login" não casaria com o domínio verificado.
        if (req.isNotifyEmail()) {
            planLimitService.checkEmailNotify(user, hostNovo);
        }

        Frequency freq = Frequency.valueOf(req.getFrequency().toUpperCase());

        // Fuso de quem cria, congelado no agendamento: a hora escolhida é a hora
        // dele, e continua sendo mesmo que ele mude de fuso depois.
        ZoneId zona = userTimeZone.zonaDe(user);

        ScheduledScan scan = ScheduledScan.builder()
                .host(hostNovo)
                .active(req.isActive())
                .frequency(freq)
                .preferredHour(Math.max(0, Math.min(23, req.getPreferredHour())))
                .nextRun(calcNextRun(freq, req.getPreferredHour(), zona))
                .enabled(true)
                .notifyEmail(req.isNotifyEmail())
                // Capturado aqui porque a execução roda fora de requisição.
                .locale(LocaleContextHolder.getLocale().toLanguageTag())
                .path(pathNovo)
                .timezone(zona.getId())
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
            scan.setNextRun(calcNextRun(scan.getFrequency(), scan.getPreferredHour(), zonaDe(scan)));
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
                        alvoDe(scan), scan.isActive(), scan.getUser(), true, ScanOrigin.SCHEDULED);

                // Persiste nextRun e lastRun em transação curta separada
                markSuccess(scan.getId(),
                        calcNextRun(scan.getFrequency(), scan.getPreferredHour(), zonaDe(scan)));

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

    /**
     * Próxima execução, em UTC — que é como a coluna nextRun é comparada com
     * LocalDateTime.now() na consulta do agendador.
     *
     * A conta é feita NO FUSO do agendamento e só então convertida: "todo dia às
     * 8h" é uma hora local, não um intervalo de 24 horas. Somar dias sobre o
     * ZonedDateTime é o que mantém as 8h nas duas metades do ano em país com
     * horário de verão — somar 24 horas sobre o instante deslocaria para 7h ou 9h
     * na virada.
     */
    static LocalDateTime calcNextRun(Frequency freq, int preferredHour, ZoneId zona) {
        ZonedDateTime agora = ZonedDateTime.now(zona);
        ZonedDateTime prox  = agora.truncatedTo(ChronoUnit.DAYS)
                                   .withHour(preferredHour);
        // Se o horário de hoje já passou, empurra para o próximo ciclo
        if (!prox.isAfter(agora)) {
            prox = prox.plusDays(freq == Frequency.WEEKLY ? 7 : 1);
        }
        return prox.withZoneSameInstant(ZoneOffset.UTC).toLocalDateTime();
    }

    /**
     * Fuso do agendamento. Criado antes da coluna existir, vem nulo e cai em UTC —
     * que é o fuso em que aquela hora foi escolhida, e continua sendo exibida.
     */
    private ZoneId zonaDe(ScheduledScan scan) {
        String id = scan.getTimezone();
        if (id == null || id.isBlank()) return UserTimeZoneService.PADRAO;
        try {
            return ZoneId.of(id);
        } catch (Exception e) {
            return UserTimeZoneService.PADRAO;
        }
    }

    /**
     * Alvo real do scan: domínio mais caminho.
     *
     * Agendamento criado antes da coluna de caminho existir vem com path nulo e
     * cai na raiz — que é o que ele já escaneava.
     */
    private static String alvoDe(ScheduledScan scan) {
        String path = scan.getPath();
        if (path == null || path.isBlank() || "/".equals(path)) return scan.getHost();
        return scan.getHost() + path;
    }

    /**
     * Caminho pedido na criação, venha ele no campo próprio ou grudado no host.
     *
     * Aceitar as duas formas é o que impede a regressão silenciosa: quem digita
     * "site.com/login" no campo de domínio continua agendando o /login, em vez de
     * ver o caminho ser descartado.
     */
    private static String caminhoPedido(ScheduledScanRequest req) {
        if (req.getPath() != null && !req.getPath().isBlank()) {
            String p = req.getPath().trim();
            return p.startsWith("/") ? p : "/" + p;
        }
        String host = req.getHost() == null ? "" : req.getHost().replaceFirst("^https?://", "");
        int barra = host.indexOf('/');
        return barra >= 0 ? host.substring(barra) : "/";
    }

    /**
     * Dois hosts são da mesma família quando só diferem pelo "www." — é o mesmo
     * site, e o histórico já os trata como um (ver ScanHistoryService.save).
     */
    static boolean mesmaFamilia(String a, String b) {
        if (a == null || b == null) return false;
        return semWww(a).equalsIgnoreCase(semWww(b));
    }

    private static String semWww(String host) {
        return host.startsWith("www.") ? host.substring(4) : host;
    }

    private String sanitizeHost(String host) {
        if (host == null) return "";
        return host.replaceFirst("^https?://", "").split("/")[0].trim().toLowerCase();
    }
}
