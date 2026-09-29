package com.joao.cyberaudit.dto;

import com.joao.cyberaudit.model.PaymentMethod;
import com.joao.cyberaudit.model.Plan;
import com.joao.cyberaudit.model.Subscription;
import com.joao.cyberaudit.model.SubscriptionStatus;
import lombok.Builder;
import lombok.Getter;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.UUID;

/** Representação de leitura da assinatura atual da conta. */
@Getter @Builder
public class SubscriptionDto {

    private UUID id;
    private Plan plan;
    private SubscriptionStatus status;
    private PaymentMethod paymentMethod;
    /** Só preenchido para PIX — até quando o plano liberado por este pagamento continua válido. */
    private LocalDateTime currentPeriodEnd;
    private BigDecimal amount;
    private String currency;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    public static SubscriptionDto from(Subscription s) {
        if (s == null) return null;
        return SubscriptionDto.builder()
                .id(s.getId())
                .plan(s.getPlan())
                .status(s.getStatus())
                .paymentMethod(s.getPaymentMethod())
                .currentPeriodEnd(s.getCurrentPeriodEnd())
                .amount(s.getAmount())
                .currency(s.getCurrency())
                .createdAt(s.getCreatedAt())
                .updatedAt(s.getUpdatedAt())
                .build();
    }
}
