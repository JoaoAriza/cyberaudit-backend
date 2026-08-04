package com.joao.cyberaudit.service;

import com.joao.cyberaudit.dto.SubscriptionDto;
import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.AccountType;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.Plan;
import com.joao.cyberaudit.model.Subscription;
import com.joao.cyberaudit.model.SubscriptionStatus;
import com.joao.cyberaudit.repository.AccountRepository;
import com.joao.cyberaudit.repository.SubscriptionRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Regras de assinatura/upgrade de plano via Mercado Pago.
 *
 * O upgrade só acontece quando o MP confirma o preapproval como AUTHORIZED — nunca só pelo
 * corpo do webhook ({@link #handleWebhook} consulta o status real na API do MP).
 */
@Service
public class BillingService {

    private final SubscriptionRepository subscriptionRepository;
    private final AccountRepository accountRepository;
    private final MercadoPagoService mpService;

    @Value("${billing.pro.amount:29.90}")        private BigDecimal proAmount;
    @Value("${billing.enterprise.amount:99.90}") private BigDecimal enterpriseAmount;
    @Value("${billing.currency:BRL}")            private String currency;
    @Value("${app.base-url:http://localhost:5173}") private String appBaseUrl;

    public BillingService(SubscriptionRepository subscriptionRepository,
                          AccountRepository accountRepository,
                          MercadoPagoService mpService) {
        this.subscriptionRepository = subscriptionRepository;
        this.accountRepository      = accountRepository;
        this.mpService              = mpService;
    }

    // ── Cliente ──────────────────────────────────────────────────────────────────

    /** Cria a assinatura no MP e devolve o init_point (URL de checkout) para redirecionar. */
    @Transactional
    public String startSubscription(AppUser user) {
        Account account = user.getAccount();
        if (account == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Conta não encontrada.");
        }
        Plan target  = targetPlan(account);
        Plan current = account.getPlan() != null ? account.getPlan() : Plan.FREE;
        if (current == target || current == Plan.ENTERPRISE) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Sua conta já está no plano " + current + ".");
        }

        BigDecimal amount = amountFor(target);
        String reason  = "CyberAudit " + (target == Plan.ENTERPRISE ? "Empresa" : "Pro");
        String backUrl = appBaseUrl + "/billing/return";

        var result = mpService.createPreapproval(
                reason, amount, currency, user.getEmail(), account.getId().toString(), backUrl);

        Subscription sub = Subscription.builder()
                .account(account)
                .plan(target)
                .mpPreapprovalId(result.id())
                .status(SubscriptionStatus.PENDING)
                .amount(amount)
                .currency(currency)
                .createdAt(LocalDateTime.now())
                .build();
        subscriptionRepository.save(sub);

        if (result.initPoint() == null || result.initPoint().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY,
                    "Mercado Pago não retornou a URL de checkout (init_point).");
        }
        return result.initPoint();
    }

    @Transactional(readOnly = true)
    public SubscriptionDto getSubscription(AppUser user) {
        Account account = user.getAccount();
        if (account == null) return null;
        return subscriptionRepository.findFirstByAccountOrderByCreatedAtDesc(account)
                .map(SubscriptionDto::from).orElse(null);
    }

    @Transactional
    public void cancelSubscription(AppUser user) {
        Account account = user.getAccount();
        if (account == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Conta não encontrada.");
        }
        Subscription sub = subscriptionRepository.findFirstByAccountOrderByCreatedAtDesc(account)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,
                        "Nenhuma assinatura encontrada."));
        if (sub.getMpPreapprovalId() != null) {
            mpService.cancelPreapproval(sub.getMpPreapprovalId());
        }
        sub.setStatus(SubscriptionStatus.CANCELLED);
        sub.setUpdatedAt(LocalDateTime.now());
        subscriptionRepository.save(sub);

        account.setPlan(Plan.FREE);
        accountRepository.save(account);
    }

    // ── Webhook (dirigido pela API do MP, não pelo corpo) ─────────────────────────

    @Transactional
    public void handleWebhook(String preapprovalId) {
        if (preapprovalId == null || preapprovalId.isBlank()) return;

        // Fonte da verdade: consulta o status real na API do MP.
        var info = mpService.getPreapproval(preapprovalId);
        SubscriptionStatus status = mapStatus(info.status());

        Subscription sub = subscriptionRepository.findByMpPreapprovalId(preapprovalId).orElse(null);
        if (sub == null) {
            // preapproval sem assinatura local — associa via external_reference (accountId)
            Account account = resolveAccount(info.externalReference());
            if (account == null) return;
            sub = Subscription.builder()
                    .account(account)
                    .plan(targetPlan(account))
                    .mpPreapprovalId(preapprovalId)
                    .status(SubscriptionStatus.PENDING)
                    .amount(amountFor(targetPlan(account)))
                    .currency(currency)
                    .createdAt(LocalDateTime.now())
                    .build();
        }

        sub.setStatus(status);
        sub.setUpdatedAt(LocalDateTime.now());
        subscriptionRepository.save(sub);

        Account account = sub.getAccount();
        if (status == SubscriptionStatus.AUTHORIZED) {
            // Confere o valor que o MP realmente cobra contra a tabela de preços antes
            // de liberar o plano. O id do preapproval sozinho não prova quanto foi pago;
            // sem esta checagem, uma assinatura de valor menor que a tabela ainda
            // resultaria em upgrade completo.
            if (!amountCoversPlan(info.amount(), sub.getPlan())) {
                System.err.println("[BillingService] upgrade recusado: preapproval " + preapprovalId
                        + " tem valor " + info.amount() + " abaixo do preço do plano " + sub.getPlan());
                return;
            }
            account.setPlan(sub.getPlan());
            accountRepository.save(account);
        } else if (status == SubscriptionStatus.CANCELLED || status == SubscriptionStatus.PAUSED) {
            account.setPlan(Plan.FREE);
            accountRepository.save(account);
        }
    }

    /**
     * true se o valor cobrado pelo MP cobre o preço configurado do plano.
     * Valor ausente na resposta do MP não bloqueia o upgrade — a API nem sempre
     * devolve auto_recurring e travar aqui deixaria cliente pagante sem acesso.
     */
    private boolean amountCoversPlan(BigDecimal mpAmount, Plan plan) {
        if (mpAmount == null) return true;
        return mpAmount.compareTo(amountFor(plan)) >= 0;
    }

    // ── Interno ──────────────────────────────────────────────────────────────────

    private Account resolveAccount(String externalReference) {
        if (externalReference == null || externalReference.isBlank()) return null;
        try {
            return accountRepository.findById(UUID.fromString(externalReference)).orElse(null);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private Plan targetPlan(Account account) {
        return account.getType() == AccountType.COMPANY ? Plan.ENTERPRISE : Plan.PRO;
    }

    private BigDecimal amountFor(Plan plan) {
        return plan == Plan.ENTERPRISE ? enterpriseAmount : proAmount;
    }

    private SubscriptionStatus mapStatus(String mpStatus) {
        if (mpStatus == null) return SubscriptionStatus.PENDING;
        return switch (mpStatus.toLowerCase()) {
            case "authorized" -> SubscriptionStatus.AUTHORIZED;
            case "paused"     -> SubscriptionStatus.PAUSED;
            case "cancelled"  -> SubscriptionStatus.CANCELLED;
            default           -> SubscriptionStatus.PENDING;
        };
    }
}
