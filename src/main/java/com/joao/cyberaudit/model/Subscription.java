package com.joao.cyberaudit.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Assinatura de uma conta, vinculada a um preapproval (CARD) ou a um payment (PIX)
 * do Mercado Pago — ver {@link PaymentMethod}. O upgrade/downgrade do
 * {@link Account#getPlan()} é dirigido pelo status desta assinatura, confirmado
 * sempre contra a API do MP (nunca só pelo corpo do webhook).
 */
@Entity
@Table(name = "subscriptions", indexes = {
        @Index(name = "idx_sub_account", columnList = "account_id"),
        @Index(name = "idx_sub_mp_preapproval", columnList = "mp_preapproval_id")
})
@Getter @Setter @Builder @NoArgsConstructor @AllArgsConstructor
public class Subscription {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "account_id", nullable = false)
    private Account account;

    /** Plano que esta assinatura concede (PRO ou ENTERPRISE). */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Plan plan;

    /** id do preapproval no Mercado Pago. Só para PaymentMethod.CARD. */
    @Column(name = "mp_preapproval_id", unique = true)
    private String mpPreapprovalId;

    /** id do payment no Mercado Pago. Só para PaymentMethod.PIX — cada ciclo é um payment novo. */
    @Column(name = "mp_payment_id", unique = true)
    private String mpPaymentId;

    /**
     * Nullable de propósito, mesmo todo registro NOVO sempre vir com um valor
     * (ver {@code @Builder.Default}): {@code ddl-auto=update} tentou adicionar esta
     * coluna como NOT NULL numa tabela de produção que já tinha linhas, e o Postgres
     * recusa isso sem um default — a migração falhava silenciosamente no boot
     * (Hibernate loga o erro e segue, a coluna nunca chegava a existir). Nullable
     * evita a migração quebrar, e toda leitura já trata NULL corretamente por
     * semântica de SQL: uma linha antiga (sempre cartão, de antes desta coluna
     * existir) nunca casa com `payment_method = 'PIX'`
     * (ver {@link com.joao.cyberaudit.repository.SubscriptionRepository#findByPaymentMethodAndStatusAndCurrentPeriodEndBefore}),
     * então o job de expiração do Pix simplesmente ignora essas linhas, que é o
     * comportamento certo.
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "payment_method", length = 10)
    @Builder.Default
    private PaymentMethod paymentMethod = PaymentMethod.CARD;

    /**
     * Até quando o plano liberado por este pagamento continua válido.
     * Só para PaymentMethod.PIX: CARD renova sozinho via preapproval e não precisa
     * de prazo — o status do MP já diz se está ativo. Ver {@link SubscriptionStatus#EXPIRED}.
     */
    @Column(name = "current_period_end")
    private LocalDateTime currentPeriodEnd;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    @Builder.Default
    private SubscriptionStatus status = SubscriptionStatus.PENDING;

    @Column(precision = 12, scale = 2)
    private BigDecimal amount;

    @Column(length = 3)
    @Builder.Default
    private String currency = "BRL";

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
}
