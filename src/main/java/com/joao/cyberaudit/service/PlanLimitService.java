package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.AccountType;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.Plan;
import com.joao.cyberaudit.model.Role;
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
 * OWNER e ADMIN recebem tratamento equivalente a ENTERPRISE em todos os checks.
 *
 * Contagem diária de scans: ConcurrentHashMap em memória, reiniciada à meia-noite.
 * Para produção multi-instância, substituir por Redis.
 */
@Service
public class PlanLimitService {

    private final DomainRepository domainRepository;

    public PlanLimitService(DomainRepository domainRepository) {
        this.domainRepository = domainRepository;
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
     * OWNER e ADMIN têm acesso equivalente a ENTERPRISE independente do plano da conta.
     */
    public Plan effectivePlan(AppUser user) {
        if (user == null) return Plan.FREE;
        if (user.getRole() == Role.OWNER || user.getRole() == Role.ADMIN) {
            return Plan.ENTERPRISE;
        }
        return effectivePlan(user.getAccount());
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
     *  OWNER / ADMIN  → sempre permitido (qualquer domínio)
     *  COMPANY        → permitido (qualquer domínio cadastrado e verificado ou não)
     *  PRO (PERSONAL) → permitido APENAS se o host (ou seu domínio pai) está verificado na conta
     *  FREE           → bloqueado
     */
    public void checkActiveScan(AppUser user, String targetHost) {
        if (user == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "Scan ativo requer autenticação.");
        }

        // OWNER / ADMIN — acesso total
        if (user.getRole() == Role.OWNER || user.getRole() == Role.ADMIN) return;

        Account account = user.getAccount();
        if (account == null) {
            throw new ResponseStatusException(HttpStatus.PAYMENT_REQUIRED,
                    "Conta não encontrada.");
        }

        // EMPRESA (COMPANY) — acesso total
        if (account.getType() == AccountType.COMPANY) return;

        // PESSOAL FREE — bloqueado
        Plan plan = effectivePlan(account);
        if (plan == Plan.FREE) {
            throw new ResponseStatusException(HttpStatus.PAYMENT_REQUIRED,
                    "Scan ativo requer plano PRO ou superior.");
        }

        // PESSOAL PRO — apenas domínios verificados na conta
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
                    "Scan ativo em modo PESSOAL só é permitido em domínios verificados na sua conta. "
                    + "Acesse Domínios, cadastre e verifique \"" + host + "\" ou faça upgrade para conta Empresa.");
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

    /** Verifica se o plano permite exportação de PDF. Lança 402 se não permitido. */
    public void checkPdfExport(AppUser user) {
        if (!effectivePlan(user).pdfExportAllowed) {
            throw new ResponseStatusException(HttpStatus.PAYMENT_REQUIRED,
                    "Exportação de PDF requer login.");
        }
    }

    /** Verifica se o plano permite acesso ao módulo de Changes. */
    public void checkChangesModule(AppUser user) {
        if (!effectivePlan(user).changesModuleAllowed) {
            throw new ResponseStatusException(HttpStatus.PAYMENT_REQUIRED,
                    "Módulo de Changes requer plano PRO ou superior.");
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
