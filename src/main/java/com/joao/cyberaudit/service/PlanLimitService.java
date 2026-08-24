package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.AccountType;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.Plan;
import com.joao.cyberaudit.repository.DomainRepository;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDate;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Aplica os limites do plano de assinatura (FREE / PRO / ENTERPRISE).
 *
 * Regras de acesso por tier — ver enum Plan para detalhes completos.
 * Só a equipe da plataforma (PLATFORM_STAFF_EMAILS) recebe tratamento equivalente
 * a ENTERPRISE; o role da conta não promove plano.
 *
 * Contagem diária de scans: ConcurrentHashMap em memória, reiniciada à meia-noite.
 * Para produção multi-instância, substituir por Redis.
 */
@Service
public class PlanLimitService {

    private final DomainRepository domainRepository;

    private final PlatformStaffService platformStaffService;

    public PlanLimitService(DomainRepository domainRepository,
                            PlatformStaffService platformStaffService) {
        this.domainRepository     = domainRepository;
        this.platformStaffService = platformStaffService;
    }

    /** "accountId:date" → scans executados hoje */
    private final ConcurrentHashMap<String, AtomicInteger> dailyCounts = new ConcurrentHashMap<>();

    // ── Reset diário ──────────────────────────────────────────────────────────

    @Scheduled(cron = "0 0 0 * * *")
    public void resetDailyCounts() {
        dailyCounts.clear();
    }

    // ── Resolução de plano efetivo ────────────────────────────────────────────

    /**
     * Plano efetivo do usuário: o da conta dele, salvo para equipe da plataforma.
     *
     * NÃO promover por {@code Role.OWNER}/{@code Role.ADMIN}: {@code /auth/register}
     * é público e cria todo cadastro já como OWNER da própria conta. Promover por
     * role fazia com que qualquer pessoa que se cadastrasse recebesse tratamento
     * ENTERPRISE — scans ilimitados, módulo de Changes, gráfico de histórico e o
     * detalhe completo do scan (impacto/correção/breakdown), tudo num plano FREE.
     *
     * É a mesma armadilha que {@link #checkActiveScan(AppUser, String)} já evitava
     * usando {@link PlatformStaffService}; o active scan foi o único check que
     * seguiu correto justamente por não olhar o role.
     */
    public Plan effectivePlan(AppUser user) {
        if (user == null) return Plan.FREE;
        if (platformStaffService.isStaff(user)) return Plan.ENTERPRISE;
        return effectivePlan(user.getAccount());
    }

    /** Equipe da plataforma — exposto para a UI decidir o que mostrar. */
    public boolean isPlatformStaff(AppUser user) {
        return platformStaffService.isStaff(user);
    }

    public Plan effectivePlan(Account account) {
        if (account == null || account.getPlan() == null) return Plan.FREE;
        return account.getPlan();
    }

    // ── Checks de plano ───────────────────────────────────────────────────────

    /**
     * Verifica e incrementa o contador diário de scans para usuários autenticados.
     * Guests são controlados por GuestRateLimitService — este método não se aplica.
     */
    public void checkAndIncrementDailyScan(AppUser user) {
        Plan plan = effectivePlan(user);
        if (plan.isUnlimited()) return;

        Account account = user.getAccount();
        if (account == null) return;

        String key   = account.getId() + ":" + LocalDate.now();
        int    count = dailyCounts.computeIfAbsent(key, k -> new AtomicInteger(0))
                                  .incrementAndGet();

        if (count > plan.dailyScanLimit) {
            dailyCounts.get(key).decrementAndGet();
            throw new ResponseStatusException(HttpStatus.PAYMENT_REQUIRED,
                    "Limite diário de " + plan.dailyScanLimit + " scans atingido. "
                    + "Faça upgrade para o plano PRO para continuar.");
        }
    }

    /**
     * Verifica se o usuário pode executar scan ativo no host-alvo.
     *
     * Regras:
     *  OWNER / ADMIN  → sempre permitido (equipe da plataforma)
     *  FREE (PESSOAL) → bloqueado
     *  PRO / EMPRESA  → permitido APENAS se o host (ou seu domínio pai) está verificado na conta
     *
     * O plano define QUANTOS domínios e com que frequência — nunca dispensa a prova
     * de posse. Scan ativo faz port scan e dispara probes de injeção a partir da
     * infra do CyberAudit: sem posse verificada, seria uma ferramenta de ataque a
     * terceiros vendida por assinatura. (Antes, conta EMPRESA passava direto.)
     */
    public void checkActiveScan(AppUser user, String targetHost) {
        if (user == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "Scan ativo requer autenticação.");
        }

        // Equipe da plataforma (lista em platform.staff-emails, vazia por padrão).
        // NÃO usar Role.OWNER aqui: /auth/register entrega OWNER a qualquer cadastro.
        if (platformStaffService.isStaff(user)) return;

        Account account = user.getAccount();
        if (account == null) {
            throw new ResponseStatusException(HttpStatus.PAYMENT_REQUIRED,
                    "Conta não encontrada.");
        }

        // PESSOAL FREE — bloqueado
        Plan plan = effectivePlan(account);
        if (plan == Plan.FREE && account.getType() != AccountType.COMPANY) {
            throw new ResponseStatusException(HttpStatus.PAYMENT_REQUIRED,
                    "Scan ativo requer plano PRO ou superior.");
        }

        if (targetHost == null || targetHost.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Host inválido para scan ativo.");
        }

        String host = normalizeHost(targetHost);

        // Verifica se o próprio host ou o domínio pai está verificado
        boolean allowed = isVerifiedForAccount(account, host)
                || isVerifiedForAccount(account, parentDomain(host));

        if (!allowed) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "Scan ativo só é permitido em domínios verificados na sua conta. "
                    + "Acesse Domínios, cadastre e verifique \"" + host + "\" para continuar.");
        }
    }

    /** Mantido para compatibilidade — chama a versão com host. */
    public void checkActiveScan(AppUser user) {
        checkActiveScan(user, null);
    }

    private boolean isVerifiedForAccount(Account account, String host) {
        if (host == null || host.isBlank()) return false;
        return domainRepository.existsByAccountAndHostAndVerifiedTrue(account, host);
    }

    private String normalizeHost(String raw) {
        if (raw == null) return "";
        return raw.trim()
                  .replaceFirst("^https?://", "")
                  .split("/")[0]
                  .toLowerCase();
    }

    /** Retorna o domínio pai (ex: "api.empresa.com.br" → "empresa.com.br"). */
    private String parentDomain(String host) {
        if (host == null) return "";
        int dot = host.indexOf('.');
        if (dot < 0 || dot == host.lastIndexOf('.')) return host; // já é raiz
        return host.substring(dot + 1);
    }

    /**
     * Verifica se o usuário pode exportar o PDF do laudo do host-alvo.
     * Ver {@link #checkReportDelivery} para as regras.
     */
    public void checkPdfExport(AppUser user, String targetHost) {
        Plan plan = effectivePlan(user);
        checkReportDelivery(user, plan, plan.pdfExportAllowed, targetHost, "Exportação de PDF");
    }

    /** Verifica se o usuário pode receber por e-mail o laudo do host-alvo. */
    public void checkEmailNotify(AppUser user, String targetHost) {
        Plan plan = effectivePlan(user);
        checkReportDelivery(user, plan, plan.emailNotifyAllowed, targetHost,
                "Notificação por e-mail");
    }

    /**
     * Variante que não lança — para o agendador, onde a exceção mataria a rodada.
     * O plano pode ter caído entre a criação do agendamento e a execução dele.
     */
    public boolean canEmailNotify(AppUser user, String targetHost) {
        try {
            checkEmailNotify(user, targetHost);
            return true;
        } catch (ResponseStatusException e) {
            return false;
        }
    }

    /**
     * Regra única de entrega de laudo, para PDF e e-mail.
     *
     *  FREE                     → bloqueado; o detalhe do achado é o produto pago
     *  PRO PESSOAL              → só sobre domínio verificado da própria conta
     *  PRO EMPRESA / ENTERPRISE → sem restrição de domínio
     *
     * A tela pode mostrar o laudo de qualquer site — é consulta. O que a posse
     * governa é o ENTREGÁVEL: sem ela, a assinatura pessoal de R$ 29,90 viraria
     * gerador de auditoria de site de terceiro em PDF timbrado.
     *
     * Não há check de staff aqui: {@link #effectivePlan(AppUser)} já promove a
     * equipe da plataforma a ENTERPRISE, que não cai na restrição de domínio.
     */
    private void checkReportDelivery(AppUser user, Plan plan, boolean allowedByPlan,
                                     String targetHost, String canal) {
        if (user == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    canal + " requer autenticação.");
        }
        if (!allowedByPlan) {
            throw new ResponseStatusException(HttpStatus.PAYMENT_REQUIRED,
                    canal + " requer plano PRO ou superior.");
        }

        Account account = user.getAccount();
        if (account == null) {
            throw new ResponseStatusException(HttpStatus.PAYMENT_REQUIRED,
                    "Conta não encontrada.");
        }

        // Só o PRO pessoal fica preso ao próprio domínio.
        if (plan != Plan.PRO || account.getType() == AccountType.COMPANY) return;

        if (targetHost == null || targetHost.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Host inválido para " + canal.toLowerCase() + ".");
        }

        String host = normalizeHost(targetHost);
        boolean owned = isVerifiedForAccount(account, host)
                || isVerifiedForAccount(account, parentDomain(host));

        if (!owned) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    canal + " no plano Pessoal Pro vale apenas para domínios verificados "
                    + "na sua conta. Acesse Domínios, cadastre e verifique \"" + host
                    + "\" para continuar.");
        }
    }

    /** Verifica se o plano permite acesso ao módulo de Changes. */
    public void checkChangesModule(AppUser user) {
        if (!effectivePlan(user).changesModuleAllowed) {
            throw new ResponseStatusException(HttpStatus.PAYMENT_REQUIRED,
                    "Módulo de Changes requer plano PRO ou superior.");
        }
    }

    /**
     * Verifica se o plano permite cadastrar domínio próprio.
     *
     * O cadastro é a porta de entrada da verificação de posse, que por sua vez
     * habilita o scan ativo — por isso o gate fica no cadastro, e não só na
     * verificação. Domínios já cadastrados antes deste limite continuam válidos.
     */
    public void checkDomainRegistration(AppUser user) {
        if (!effectivePlan(user).domainRegistrationAllowed) {
            throw new ResponseStatusException(HttpStatus.PAYMENT_REQUIRED,
                    "Cadastro de domínio requer plano PRO ou superior.");
        }
    }

    /**
     * Verifica se o plano permite os relatórios da conta: log de auditoria,
     * PDF executivo e página de status pública.
     *
     * Gestão de equipe (usuários, convites, 2FA) NÃO passa por aqui de propósito —
     * continua valendo só o role, senão uma conta COMPANY FREE não conseguiria
     * montar o próprio time.
     */
    public void checkReportsModule(AppUser user) {
        if (!effectivePlan(user).reportsModuleAllowed) {
            throw new ResponseStatusException(HttpStatus.PAYMENT_REQUIRED,
                    "Relatórios da conta requerem plano PRO ou superior.");
        }
    }

    /** Verifica se o plano permite acesso ao gráfico de histórico de score. */
    public void checkHistoryChart(AppUser user) {
        if (!effectivePlan(user).historyChartAllowed) {
            throw new ResponseStatusException(HttpStatus.PAYMENT_REQUIRED,
                    "Histórico de score requer plano PRO ou superior.");
        }
    }

    /**
     * Verifica se o número de agendamentos não ultrapassa o limite do plano.
     * @param user         Usuário autenticado
     * @param currentCount Nº de agendamentos existentes do usuário
     */
    public void checkScheduledScanSlots(AppUser user, int currentCount) {
        Plan plan = effectivePlan(user);
        if (plan.scheduledScanLimit < 0) return;
        if (currentCount >= plan.scheduledScanLimit) {
            throw new ResponseStatusException(HttpStatus.PAYMENT_REQUIRED,
                    "Limite de " + plan.scheduledScanLimit
                    + " agendamentos atingido para o plano " + plan.name()
                    + ". Faça upgrade para adicionar mais.");
        }
    }

    // ── Consulta ──────────────────────────────────────────────────────────────

    /** @return scans restantes hoje, ou -1 se ilimitado. */
    public int getRemainingScans(AppUser user) {
        Plan plan = effectivePlan(user);
        if (plan.isUnlimited()) return -1;

        Account account = user != null ? user.getAccount() : null;
        if (account == null) return plan.dailyScanLimit;

        String key  = account.getId() + ":" + LocalDate.now();
        int    used = dailyCounts.getOrDefault(key, new AtomicInteger(0)).get();
        return Math.max(0, plan.dailyScanLimit - used);
    }

    /** @return scans restantes por Account (para compatibilidade com UserDto). */
    public int getRemainingScans(Account account) {
        Plan plan = effectivePlan(account);
        if (plan.isUnlimited()) return -1;
        if (account == null) return plan.dailyScanLimit;

        String key  = account.getId() + ":" + LocalDate.now();
        int    used = dailyCounts.getOrDefault(key, new AtomicInteger(0)).get();
        return Math.max(0, plan.dailyScanLimit - used);
    }
}
