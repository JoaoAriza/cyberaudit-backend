package com.joao.cyberaudit.service;

import com.joao.cyberaudit.dto.PixCheckoutDto;
import com.joao.cyberaudit.dto.SubscriptionDto;
import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.AccountType;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.PaymentMethod;
import com.joao.cyberaudit.model.Plan;
import com.joao.cyberaudit.model.Subscription;
import com.joao.cyberaudit.model.SubscriptionStatus;
import com.joao.cyberaudit.repository.AccountRepository;
import com.joao.cyberaudit.repository.SubscriptionRepository;
import com.joao.cyberaudit.util.CpfUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Regras de assinatura/upgrade de plano via Mercado Pago — duas formas de pagar,
 * ambas em tela própria (checkout transparente, sem redirecionar pro MP):
 *
 *  cartão (startCardCheckout) → card_token_id, recorrente de verdade.
 *  Pix (startPixCheckout)     → pagamento único por ciclo, sem débito automático —
 *                                {@link #expirarAssinaturasPixVencidas()} rebaixa a
 *                                conta quando o período vence sem renovar.
 *
 * O upgrade só acontece quando o MP confirma o pagamento/preapproval — nunca só pelo corpo
 * do webhook ({@link #handleWebhook}/{@link #handlePaymentWebhook} sempre consultam a API do MP).
 */
@Service
public class BillingService {

    private final SubscriptionRepository subscriptionRepository;
    private final AccountRepository accountRepository;
    private final MercadoPagoService mpService;

    @Value("${billing.pro.amount:19.99}")        private BigDecimal proAmount;
    @Value("${billing.enterprise.amount:59.99}") private BigDecimal enterpriseAmount;
    @Value("${billing.currency:BRL}")            private String currency;
    @Value("${app.base-url:http://localhost:5173}") private String appBaseUrl;

    public BillingService(SubscriptionRepository subscriptionRepository,
                          AccountRepository accountRepository,
                          MercadoPagoService mpService) {
        this.subscriptionRepository = subscriptionRepository;
        this.accountRepository      = accountRepository;
        this.mpService              = mpService;
    }

    // ── Checkout transparente (tela própria) ──────────────────────────────────────

    /**
     * Assina via cartão tokenizado no navegador (checkout transparente) — sem
     * redirecionamento. {@code cardTokenId} vem do SDK do MP (mp.cardForm), nunca
     * número de cartão cru.
     *
     * Diferente do webhook: aqui a resposta vem de uma chamada NOSSA, autenticada,
     * direto para a API do MP — não é entrada de terceiro não confiável como o
     * corpo de um webhook, então pode liberar o plano na hora quando authorized.
     */
    @Transactional
    public SubscriptionDto startCardCheckout(AppUser user, Plan escolhido, String cardTokenId) {
        if (cardTokenId == null || cardTokenId.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "cardTokenId ausente — gere o token no navegador antes de chamar este endpoint.");
        }
        Account account = user.getAccount();
        Plan target = validateUpgradeTarget(account, escolhido);

        BigDecimal amount = amountFor(target);
        String backUrl = appBaseUrl + "/billing/return";

        var result = mpService.createPreapprovalWithCard(reasonFor(target), amount, currency,
                user.getEmail(), account.getId().toString(), backUrl, cardTokenId);

        Subscription sub = Subscription.builder()
                .account(account)
                .plan(target)
                .mpPreapprovalId(result.id())
                .paymentMethod(PaymentMethod.CARD)
                .status(mapStatus(result.status()))
                .amount(amount)
                .currency(currency)
                .createdAt(LocalDateTime.now())
                .build();

        if (sub.getStatus() == SubscriptionStatus.AUTHORIZED) {
            account.setPlan(target);
            accountRepository.save(account);
        }
        subscriptionRepository.save(sub);
        return SubscriptionDto.from(sub);
    }

    /**
     * Cria um pagamento Pix único pelo preço do plano (1 ciclo de 30 dias — Pix comum
     * não tem débito automático, ver {@link PaymentMethod#PIX}). Devolve o QR code e o
     * copia-e-cola prontos; o plano só é liberado quando o webhook confirmar o
     * pagamento como aprovado ({@link #handlePaymentWebhook}).
     *
     * @param cpfBruto CPF do pagador, com ou sem pontuação — normalizado aqui.
     */
    @Transactional
    public PixCheckoutDto startPixCheckout(AppUser user, Plan escolhido, String cpfBruto) {
        String cpf = somenteDigitos(cpfBruto);
        if (cpf.length() != 11) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "CPF inválido: informe os 11 dígitos, com ou sem pontuação.");
        }
        if (!CpfUtil.isValid(cpf)) {
            // Não ecoa o CPF na mensagem — é dado pessoal, e o erro já aparece na tela.
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "CPF inválido: dígito verificador não confere.");
        }
        Account account = user.getAccount();
        Plan target = validateUpgradeTarget(account, escolhido);

        BigDecimal amount = amountFor(target);
        var result = mpService.createPixPayment(amount, currency, user.getEmail(), cpf,
                reasonFor(target), account.getId().toString());

        if (result.id() == null || (result.qrCode() == null && result.qrCodeBase64() == null)) {
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY,
                    "Mercado Pago não retornou o QR code do Pix.");
        }

        Subscription sub = Subscription.builder()
                .account(account)
                .plan(target)
                .mpPaymentId(result.id())
                .paymentMethod(PaymentMethod.PIX)
                .status(SubscriptionStatus.PENDING)
                .amount(amount)
                .currency(currency)
                .createdAt(LocalDateTime.now())
                .build();
        subscriptionRepository.save(sub);

        return PixCheckoutDto.builder()
                .subscriptionId(sub.getId())
                .paymentId(result.id())
                .status(result.status())
                .qrCode(result.qrCode())
                .qrCodeBase64(result.qrCodeBase64())
                .ticketUrl(result.ticketUrl())
                .build();
    }

    @Transactional(readOnly = true)
    public SubscriptionDto getSubscription(AppUser user) {
        Account account = user.getAccount();
        if (account == null) return null;
        return currentSubscription(account).map(SubscriptionDto::from).orElse(null);
    }

    /**
     * Assinatura "atual" de uma conta: a mais recente AUTHORIZED, ou — se nunca
     * houve nenhuma — a mais recente de qualquer status.
     *
     * Sem isto, {@code findFirstByAccountOrderByCreatedAtDesc} sozinho pegava
     * sempre a linha mais NOVA por data, ponto. Um Pix pago (AUTHORIZED) seguido
     * de um segundo Pix gerado pra testar de novo e nunca pago (PENDING) fazia o
     * pago desaparecer de {@code GET /billing/subscription} — aconteceu de
     * verdade validando o checkout Pix em produção (ver HANDOFF.md, seção 2 item 9).
     * Pior em {@link #cancelSubscription}: cancelar rebaixava a conta pra FREE
     * mesmo com uma assinatura paga ativa, se um checkout abandonado mais novo
     * existisse por cima dela.
     */
    private Optional<Subscription> currentSubscription(Account account) {
        return subscriptionRepository
                .findFirstByAccountAndStatusOrderByCreatedAtDesc(account, SubscriptionStatus.AUTHORIZED)
                .or(() -> subscriptionRepository.findFirstByAccountOrderByCreatedAtDesc(account));
    }

    @Transactional
    public void cancelSubscription(AppUser user) {
        Account account = user.getAccount();
        if (account == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Conta não encontrada.");
        }
        Subscription sub = currentSubscription(account)
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

            // Preapproval sem registro local (assinatura criada fora do fluxo, ou
            // registro perdido). O plano vem do VALOR que o MP está cobrando, não
            // do tipo da conta: o valor é o que o cliente de fato contratou, e
            // adivinhar pelo tipo daria ENTERPRISE a quem pagou por PRO.
            Plan planoPago = planoPeloValor(info.amount());
            if (planoPago == null) {
                System.err.println("[BillingService] preapproval " + preapprovalId
                        + " com valor " + info.amount() + " não corresponde a nenhum plano da tabela.");
                return;
            }

            sub = Subscription.builder()
                    .account(account)
                    .plan(planoPago)
                    .mpPreapprovalId(preapprovalId)
                    .status(SubscriptionStatus.PENDING)
                    .amount(amountFor(planoPago))
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
     * Webhook de payment (Pix) — id vem do topic "payment", nunca "preapproval".
     * Só a transição para "approved" importa aqui: qualquer outro status (rejected,
     * cancelled) não mexe no plano — Pix não tem débito automático, então um pagamento
     * de renovação recusado não derruba quem ainda está dentro do período já pago.
     * Quem derruba é o job diário {@link #expirarAssinaturasPixVencidas()}, quando o
     * período realmente vence sem um pagamento aprovado novo.
     */
    @Transactional
    public void handlePaymentWebhook(String paymentId) {
        if (paymentId == null || paymentId.isBlank()) return;

        var info = mpService.getPayment(paymentId);
        if (!"approved".equalsIgnoreCase(info.status())) return;

        Subscription sub = subscriptionRepository.findByMpPaymentId(paymentId).orElse(null);
        if (sub == null) {
            System.err.println("[BillingService] payment " + paymentId
                    + " aprovado sem Subscription local (mpPaymentId não encontrado).");
            return;
        }
        if (sub.getStatus() == SubscriptionStatus.AUTHORIZED) return; // já processado (webhook pode repetir)

        if (!amountCoversPlan(info.amount(), sub.getPlan())) {
            System.err.println("[BillingService] upgrade Pix recusado: payment " + paymentId
                    + " tem valor " + info.amount() + " abaixo do preço do plano " + sub.getPlan());
            return;
        }

        LocalDateTime agora = LocalDateTime.now();
        sub.setStatus(SubscriptionStatus.AUTHORIZED);
        sub.setCurrentPeriodEnd(agora.plusDays(30));
        sub.setUpdatedAt(agora);
        subscriptionRepository.save(sub);

        Account account = sub.getAccount();
        account.setPlan(sub.getPlan());
        accountRepository.save(account);
    }

    // ── Expiração de assinaturas Pix (sem débito automático) ──────────────────────

    /**
     * Roda 1x/dia: rebaixa para FREE toda conta cuja assinatura Pix passou do
     * currentPeriodEnd sem um pagamento novo aprovado. Cartão não entra aqui — ele
     * renova sozinho via preapproval, e o status vindo do MP já reflete falha de cobrança.
     */
    @Scheduled(cron = "0 0 3 * * *")
    @Transactional
    public void expirarAssinaturasPixVencidas() {
        List<Subscription> vencidas = subscriptionRepository
                .findByPaymentMethodAndStatusAndCurrentPeriodEndBefore(
                        PaymentMethod.PIX, SubscriptionStatus.AUTHORIZED, LocalDateTime.now());

        for (Subscription sub : vencidas) {
            sub.setStatus(SubscriptionStatus.EXPIRED);
            sub.setUpdatedAt(LocalDateTime.now());
            subscriptionRepository.save(sub);

            Account account = sub.getAccount();
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

    /**
     * Plano a contratar: o escolhido pelo cliente, ou o sugerido pelo tipo de conta.
     *
     * O padrão por tipo continua porque é o palpite certo na maioria dos casos —
     * mas não pode ser imposição: uma conta EMPRESA pequena pode querer o PRO, e
     * uma conta pessoal pode querer os recursos do ENTERPRISE. Só FREE é recusado:
     * não é algo que se assine.
     */
    /**
     * Valida conta + plano-alvo para QUALQUER fluxo de checkout (hospedado,
     * cartão transparente ou Pix) — as três regras (conta existe, não é o plano
     * atual, não é downgrade por nova assinatura) são as mesmas nos três.
     */
    private Plan validateUpgradeTarget(Account account, Plan escolhido) {
        if (account == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Conta não encontrada.");
        }
        Plan target  = targetPlan(account, escolhido);
        Plan current = account.getPlan() != null ? account.getPlan() : Plan.FREE;

        if (current == target) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Sua conta já está no plano " + current + ".");
        }
        // Impede DOWNGRADE por nova assinatura: sair de ENTERPRISE para PRO assim
        // criaria uma segunda cobrança sem cancelar a primeira. Downgrade se faz
        // cancelando a assinatura atual e contratando de novo.
        if (current == Plan.ENTERPRISE && target == Plan.PRO) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Para trocar de ENTERPRISE para PRO, cancele a assinatura atual primeiro.");
        }
        return target;
    }

    private String reasonFor(Plan plan) {
        return "CyberAudit " + (plan == Plan.ENTERPRISE ? "Empresa" : "Pro");
    }

    /** Remove tudo que não é dígito — cliente pode mandar CPF com ou sem pontuação. */
    private String somenteDigitos(String raw) {
        return raw == null ? "" : raw.replaceAll("\\D", "");
    }

    private Plan targetPlan(Account account, Plan escolhido) {
        if (escolhido == null) {
            return account.getType() == AccountType.COMPANY ? Plan.ENTERPRISE : Plan.PRO;
        }
        if (escolhido == Plan.FREE) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "FREE não é um plano contratável. Escolha PRO ou ENTERPRISE.");
        }
        return escolhido;
    }

    /**
     * Qual plano o valor cobrado paga. Null quando não alcança nem o mais barato.
     *
     * Compara do mais caro para o mais barato para que um valor acima do
     * ENTERPRISE não seja classificado como PRO.
     */
    private Plan planoPeloValor(BigDecimal valor) {
        if (valor == null) return null;
        if (valor.compareTo(enterpriseAmount) >= 0) return Plan.ENTERPRISE;
        if (valor.compareTo(proAmount)        >= 0) return Plan.PRO;
        return null;
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
