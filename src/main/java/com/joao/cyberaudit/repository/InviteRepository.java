package com.joao.cyberaudit.repository;

import com.joao.cyberaudit.model.Invite;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface InviteRepository extends JpaRepository<Invite, UUID> {

    Optional<Invite> findByToken(String token);

    @Query("SELECT i FROM Invite i WHERE i.accepted = false AND i.expiresAt > :now")
    List<Invite> findPending(LocalDateTime now);

    @Modifying
    @Transactional
    @Query("DELETE FROM Invite i WHERE i.expiresAt < :now AND i.accepted = false")
    void deleteExpired(LocalDateTime now);

    boolean existsByEmailAndAcceptedFalse(String email);

    /** Exclusão de conta: remove todos os convites da conta. */
    @Modifying
    @Transactional
    @Query("DELETE FROM Invite i WHERE i.account.id = :accountId")
    void deleteByAccountId(java.util.UUID accountId);

    /** Exclusão de conta: remove convites criados por este usuário. */
    @Modifying
    @Transactional
    @Query("DELETE FROM Invite i WHERE i.invitedBy.id = :userId")
    void deleteByInvitedById(java.util.UUID userId);
}