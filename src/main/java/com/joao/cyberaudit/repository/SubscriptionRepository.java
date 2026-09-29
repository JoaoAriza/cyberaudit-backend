package com.joao.cyberaudit.repository;

import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.PaymentMethod;
import com.joao.cyberaudit.model.Subscription;
import com.joao.cyberaudit.model.SubscriptionStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface SubscriptionRepository extends JpaRepository<Subscription, UUID> {

    /** Exclusão de conta (LGPD): remove as assinaturas da conta. */
    void deleteByAccount(Account account);

    Optional<Subscription> findByMpPreapprovalId(String mpPreapprovalId);

    Optional<Subscription> findByMpPaymentId(String mpPaymentId);

    /** Assinatura mais recente de uma conta (a "atual"). */
    Optional<Subscription> findFirstByAccountOrderByCreatedAtDesc(Account account);

    /** Assinaturas PIX ativas cujo período venceu sem um pagamento novo — ver o job diário em BillingService. */
    List<Subscription> findByPaymentMethodAndStatusAndCurrentPeriodEndBefore(
            PaymentMethod paymentMethod, SubscriptionStatus status, LocalDateTime cutoff);
}
