package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.AccountType;
import com.joao.cyberaudit.model.Plan;
import com.joao.cyberaudit.model.Subscription;
import com.joao.cyberaudit.model.SubscriptionStatus;
import com.joao.cyberaudit.repository.AccountRepository;
import com.joao.cyberaudit.repository.SubscriptionRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.math.BigDecimal;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Caminho do dinheiro: o webhook do MP só pode liberar plano quando o Mercado Pago
 * confirma status AUTHORIZED E o valor cobrado cobre o preço configurado.
 */
class BillingServiceTest {

    private static final BigDecimal PRO_PRICE = new BigDecimal("29.90");

    private SubscriptionRepository subscriptionRepository;
    private AccountRepository      accountRepository;
    private MercadoPagoService     mpService;
    private BillingService         billingService;

    private Account      account;
    private Subscription subscription;

    @BeforeEach
    void setUp() {
        subscriptionRepository = mock(SubscriptionRepository.class);
        accountRepository      = mock(AccountRepository.class);
        mpService              = mock(MercadoPagoService.class);

        billingService = new BillingService(subscriptionRepository, accountRepository, mpService);
        ReflectionTestUtils.setField(billingService, "proAmount", PRO_PRICE);
        ReflectionTestUtils.setField(billingService, "enterpriseAmount", new BigDecimal("99.90"));
        ReflectionTestUtils.setField(billingService, "currency", "BRL");

        account = Account.builder()
                .id(UUID.randomUUID())
                .type(AccountType.INDIVIDUAL)
                .plan(Plan.FREE)
                .build();

        subscription = Subscription.builder()
                .account(account)
                .plan(Plan.PRO)
                .mpPreapprovalId("preapproval-1")
                .status(SubscriptionStatus.PENDING)
                .build();

        when(subscriptionRepository.findByMpPreapprovalId(anyString()))
                .thenReturn(Optional.of(subscription));
    }

    private void mpReturns(String status, BigDecimal amount) {
        when(mpService.getPreapproval(anyString())).thenReturn(
                new MercadoPagoService.PreapprovalInfo(
                        "preapproval-1", status, account.getId().toString(), amount, "BRL"));
    }

    @Test
    @DisplayName("authorized com valor da tabela libera o plano")
    void autorizadoComValorCorretoLiberaPlano() {
        mpReturns("authorized", PRO_PRICE);

        billingService.handleWebhook("preapproval-1");

        assertEquals(Plan.PRO, account.getPlan());
        verify(accountRepository).save(account);
    }

    @Test
    @DisplayName("authorized com valor ABAIXO do preço não libera o plano")
    void valorAbaixoNaoLiberaPlano() {
        mpReturns("authorized", new BigDecimal("0.01"));

        billingService.handleWebhook("preapproval-1");

        assertEquals(Plan.FREE, account.getPlan(), "conta não pode subir de plano pagando centavos");
        verify(accountRepository, never()).save(any(Account.class));
    }

    @Test
    @DisplayName("valor acima do preço (promoção/reajuste) continua liberando")
    void valorAcimaLibera() {
        mpReturns("authorized", new BigDecimal("49.90"));

        billingService.handleWebhook("preapproval-1");

        assertEquals(Plan.PRO, account.getPlan());
    }

    @Test
    @DisplayName("MP sem auto_recurring na resposta não bloqueia cliente pagante")
    void valorAusenteNaoBloqueia() {
        mpReturns("authorized", null);

        billingService.handleWebhook("preapproval-1");

        assertEquals(Plan.PRO, account.getPlan());
    }

    @Test
    @DisplayName("status pending não libera o plano")
    void pendingNaoLibera() {
        mpReturns("pending", PRO_PRICE);

        billingService.handleWebhook("preapproval-1");

        assertEquals(Plan.FREE, account.getPlan());
        assertEquals(SubscriptionStatus.PENDING, subscription.getStatus());
    }

    @Test
    @DisplayName("cancelamento derruba a conta para FREE")
    void canceladoVoltaParaFree() {
        account.setPlan(Plan.PRO);
        mpReturns("cancelled", PRO_PRICE);

        billingService.handleWebhook("preapproval-1");

        assertEquals(Plan.FREE, account.getPlan());
        assertEquals(SubscriptionStatus.CANCELLED, subscription.getStatus());
    }

    @Test
    @DisplayName("webhook duplicado é idempotente — não muda nada na segunda vez")
    void webhookDuplicadoEIdempotente() {
        mpReturns("authorized", PRO_PRICE);

        billingService.handleWebhook("preapproval-1");
        billingService.handleWebhook("preapproval-1");

        assertEquals(Plan.PRO, account.getPlan());
        assertEquals(SubscriptionStatus.AUTHORIZED, subscription.getStatus());
    }

    @Test
    @DisplayName("id vazio não chega a consultar o Mercado Pago")
    void idVazioNaoConsultaMp() {
        billingService.handleWebhook("");
        billingService.handleWebhook(null);

        verify(mpService, never()).getPreapproval(anyString());
    }
}
