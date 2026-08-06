package com.joao.cyberaudit.repository;

import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.Subscription;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface SubscriptionRepository extends JpaRepository<Subscription, UUID> {

    /** Exclusão de conta (LGPD): remove as assinaturas da conta. */
    void deleteByAccount(Account account);

    Optional<Subscription> findByMpPreapprovalId(String mpPreapprovalId);

    /** Assinatura mais recente de uma conta (a "atual"). */
    Optional<Subscription> findFirstByAccountOrderByCreatedAtDesc(Account account);
}
