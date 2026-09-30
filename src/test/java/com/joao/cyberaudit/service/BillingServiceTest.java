package com.joao.cyberaudit.service;

import com.joao.cyberaudit.dto.PixCheckoutDto;
import com.joao.cyberaudit.dto.SubscriptionDto;
import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.AccountType;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.PaymentMethod;
import com.joao.cyberaudit.model.Plan;
import com.joao.cyberaudit.model.Role;
import com.joao.cyberaudit.model.Subscription;
import com.joao.cyberaudit.model.SubscriptionStatus;
import com.joao.cyberaudit.repository.AccountRepository;
import com.joao.cyberaudit.repository.SubscriptionRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ResponseStatusException;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
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

    private static final BigDecimal PRO_PRICE = new BigDecimal("19.99");

    private SubscriptionRepository subscriptionRepository;
    private AccountRepository      accountRepository;
    private MercadoPagoService     mpService;
    private BillingService         billingService;

    private Account      account;
    private AppUser      user;
    private Subscription subscription;

    @BeforeEach
    void setUp() {
        subscriptionRepository = mock(SubscriptionRepository.class);
        accountRepository      = mock(AccountRepository.class);
        mpService              = mock(MercadoPagoService.class);

        billingService = new BillingService(subscriptionRepository, accountRepository, mpService);
        ReflectionTestUtils.setField(billingService, "proAmount", PRO_PRICE);
        ReflectionTestUtils.setField(billingService, "enterpriseAmount", new BigDecimal("59.99"));
        ReflectionTestUtils.setField(billingService, "currency", "BRL");

        account = Account.builder()
                .id(UUID.randomUUID())
                .type(AccountType.INDIVIDUAL)
                .plan(Plan.FREE)
                .build();

        user = AppUser.builder()
                .id(UUID.randomUUID())
                .email("cliente@example.com")
                .role(Role.OWNER)
                .account(account)
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

    // ── Checkout transparente: cartão ──────────────────────────────────────────

    @Test
    @DisplayName("cartão authorized na criação libera o plano na hora, sem esperar webhook")
    void cartaoAuthorizedLiberaNaHora() {
        when(mpService.createPreapprovalWithCard(anyString(), any(), anyString(), anyString(),
                anyString(), anyString(), anyString()))
                .thenReturn(new MercadoPagoService.PreapprovalResult("preapproval-novo", "authorized"));

        SubscriptionDto dto = billingService.startCardCheckout(user, Plan.PRO, "card-token-abc");

        assertEquals(Plan.PRO, account.getPlan());
        assertEquals(SubscriptionStatus.AUTHORIZED, dto.getStatus());
        assertEquals(PaymentMethod.CARD, dto.getPaymentMethod());
        verify(accountRepository).save(account);
    }

    @Test
    @DisplayName("cartão pending na criação não libera o plano ainda")
    void cartaoPendingNaoLiberaAinda() {
        when(mpService.createPreapprovalWithCard(anyString(), any(), anyString(), anyString(),
                anyString(), anyString(), anyString()))
                .thenReturn(new MercadoPagoService.PreapprovalResult("preapproval-novo", "pending"));

        billingService.startCardCheckout(user, Plan.PRO, "card-token-abc");

        assertEquals(Plan.FREE, account.getPlan());
        verify(accountRepository, never()).save(any(Account.class));
    }

    @Test
    @DisplayName("checkout de cartão sem cardTokenId — 400, nem chama o Mercado Pago")
    void cartaoSemTokenRecusa() {
        var erro = assertThrows(ResponseStatusException.class,
                () -> billingService.startCardCheckout(user, Plan.PRO, "  "));

        assertEquals(HttpStatus.BAD_REQUEST, erro.getStatusCode());
        verify(mpService, never()).createPreapprovalWithCard(
                anyString(), any(), anyString(), anyString(), anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("checkout de cartão reusa a mesma regra de upgrade — já no plano recusa")
    void cartaoJaNoPlanoRecusa() {
        account.setPlan(Plan.PRO);

        var erro = assertThrows(ResponseStatusException.class,
                () -> billingService.startCardCheckout(user, Plan.PRO, "card-token-abc"));

        assertEquals(HttpStatus.CONFLICT, erro.getStatusCode());
    }

    // ── Checkout transparente: Pix ──────────────────────────────────────────────

    private void mpPixReturns(String id, String status, String qrCode) {
        when(mpService.createPixPayment(any(), anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(new MercadoPagoService.PixPaymentResult(id, status, qrCode, "base64img", "https://ticket"));
    }

    @Test
    @DisplayName("Pix cria o pagamento e devolve QR code, mas NÃO libera o plano ainda")
    void pixCriaPagamentoSemLiberarPlano() {
        mpPixReturns("payment-1", "pending", "00020126...");

        PixCheckoutDto dto = billingService.startPixCheckout(user, Plan.PRO, "111.444.777-35");

        assertEquals("payment-1", dto.getPaymentId());
        assertEquals("00020126...", dto.getQrCode());
        assertEquals(Plan.FREE, account.getPlan(), "Pix só libera quando o webhook confirmar approved");
        verify(accountRepository, never()).save(any(Account.class));
    }

    @Test
    @DisplayName("CPF é normalizado (aceita com pontuação) antes de ir pro Mercado Pago")
    void cpfComPontuacaoENormalizado() {
        mpPixReturns("payment-1", "pending", "00020126...");

        billingService.startPixCheckout(user, Plan.PRO, "111.444.777-35");

        verify(mpService).createPixPayment(any(), anyString(), anyString(),
                org.mockito.ArgumentMatchers.eq("11144477735"), anyString(), anyString());
    }

    @Test
    @DisplayName("CPF inválido (tamanho errado) — 400, nem chama o Mercado Pago")
    void cpfInvalidoRecusa() {
        var erro = assertThrows(ResponseStatusException.class,
                () -> billingService.startPixCheckout(user, Plan.PRO, "123"));

        assertEquals(HttpStatus.BAD_REQUEST, erro.getStatusCode());
        verify(mpService, never()).createPixPayment(any(), anyString(), anyString(), anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("CPF com 11 dígitos mas dígito verificador inválido — 400, nem chama o Mercado Pago")
    void cpfComDigitoVerificadorInvalidoRecusa() {
        var erro = assertThrows(ResponseStatusException.class,
                () -> billingService.startPixCheckout(user, Plan.PRO, "111.444.777-36"));

        assertEquals(HttpStatus.BAD_REQUEST, erro.getStatusCode());
        verify(mpService, never()).createPixPayment(any(), anyString(), anyString(), anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("Mercado Pago sem QR code na resposta — 502, não salva Subscription quebrada")
    void pixSemQrCodeFalha() {
        when(mpService.createPixPayment(any(), anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(new MercadoPagoService.PixPaymentResult("payment-1", "pending", null, null, null));

        var erro = assertThrows(ResponseStatusException.class,
                () -> billingService.startPixCheckout(user, Plan.PRO, "111.444.777-35"));

        assertEquals(HttpStatus.BAD_GATEWAY, erro.getStatusCode());
        verify(subscriptionRepository, never()).save(any());
    }

    // ── Webhook de payment (Pix) ─────────────────────────────────────────────────

    private Subscription subscricaoPix() {
        Subscription sub = Subscription.builder()
                .account(account)
                .plan(Plan.PRO)
                .mpPaymentId("payment-1")
                .paymentMethod(PaymentMethod.PIX)
                .status(SubscriptionStatus.PENDING)
                .build();
        when(subscriptionRepository.findByMpPaymentId("payment-1")).thenReturn(Optional.of(sub));
        return sub;
    }

    private void mpPaymentReturns(String status, BigDecimal amount) {
        when(mpService.getPayment("payment-1")).thenReturn(
                new MercadoPagoService.PaymentInfo("payment-1", status, account.getId().toString(), amount, "BRL"));
    }

    @Test
    @DisplayName("payment approved libera o plano e marca currentPeriodEnd ~30 dias à frente")
    void paymentApprovedLiberaPlanoComPeriodo() {
        Subscription sub = subscricaoPix();
        mpPaymentReturns("approved", PRO_PRICE);

        billingService.handlePaymentWebhook("payment-1");

        assertEquals(Plan.PRO, account.getPlan());
        assertEquals(SubscriptionStatus.AUTHORIZED, sub.getStatus());
        assertNotNull(sub.getCurrentPeriodEnd());
        assertTrue(sub.getCurrentPeriodEnd().isAfter(LocalDateTime.now().plusDays(29)));
    }

    @Test
    @DisplayName("payment rejected não mexe no plano nem no status — Pix não tem downgrade automático por falha de renovação")
    void paymentRejectedNaoMuda() {
        Subscription sub = subscricaoPix();
        mpPaymentReturns("rejected", PRO_PRICE);

        billingService.handlePaymentWebhook("payment-1");

        assertEquals(Plan.FREE, account.getPlan());
        assertEquals(SubscriptionStatus.PENDING, sub.getStatus());
    }

    @Test
    @DisplayName("payment approved com valor abaixo do preço não libera o plano")
    void paymentApprovedValorAbaixoNaoLibera() {
        subscricaoPix();
        mpPaymentReturns("approved", new BigDecimal("0.01"));

        billingService.handlePaymentWebhook("payment-1");

        assertEquals(Plan.FREE, account.getPlan());
    }

    @Test
    @DisplayName("webhook de payment duplicado é idempotente")
    void paymentWebhookDuplicadoEIdempotente() {
        Subscription sub = subscricaoPix();
        mpPaymentReturns("approved", PRO_PRICE);

        billingService.handlePaymentWebhook("payment-1");
        LocalDateTime primeiroPeriodo = sub.getCurrentPeriodEnd();
        billingService.handlePaymentWebhook("payment-1");

        assertEquals(primeiroPeriodo, sub.getCurrentPeriodEnd(), "segunda chamada não deveria reprocessar");
    }

    @Test
    @DisplayName("mpPaymentId sem Subscription local não quebra — só loga e sai")
    void paymentSemSubscriptionLocalNaoQuebra() {
        mpPaymentReturns("approved", PRO_PRICE);
        when(subscriptionRepository.findByMpPaymentId("payment-1")).thenReturn(Optional.empty());

        billingService.handlePaymentWebhook("payment-1");

        assertEquals(Plan.FREE, account.getPlan());
    }

    // ── Job de expiração de assinaturas Pix ──────────────────────────────────────

    @Test
    @DisplayName("assinatura Pix vencida sem renovação rebaixa a conta para FREE")
    void assinaturaPixVencidaRebaixaConta() {
        account.setPlan(Plan.PRO);
        Subscription vencida = Subscription.builder()
                .account(account)
                .plan(Plan.PRO)
                .paymentMethod(PaymentMethod.PIX)
                .status(SubscriptionStatus.AUTHORIZED)
                .currentPeriodEnd(LocalDateTime.now().minusDays(1))
                .build();
        when(subscriptionRepository.findByPaymentMethodAndStatusAndCurrentPeriodEndBefore(
                org.mockito.ArgumentMatchers.eq(PaymentMethod.PIX),
                org.mockito.ArgumentMatchers.eq(SubscriptionStatus.AUTHORIZED),
                any())).thenReturn(List.of(vencida));

        billingService.expirarAssinaturasPixVencidas();

        assertEquals(SubscriptionStatus.EXPIRED, vencida.getStatus());
        assertEquals(Plan.FREE, account.getPlan());
    }

    @Test
    @DisplayName("nenhuma assinatura vencida — job não toca em nada")
    void semAssinaturaVencidaJobNaoFazNada() {
        account.setPlan(Plan.PRO);
        when(subscriptionRepository.findByPaymentMethodAndStatusAndCurrentPeriodEndBefore(
                any(), any(), any())).thenReturn(List.of());

        billingService.expirarAssinaturasPixVencidas();

        assertEquals(Plan.PRO, account.getPlan());
        verify(accountRepository, never()).save(any(Account.class));
    }
}
