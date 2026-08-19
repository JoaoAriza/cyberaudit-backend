package com.joao.cyberaudit.repository;

import com.joao.cyberaudit.model.PasswordResetToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, UUID> {

    /** A busca é sempre pelo hash — o token em claro nunca chega ao banco. */
    Optional<PasswordResetToken> findByTokenHashAndUsedFalse(String tokenHash);

    /** Invalida pedidos anteriores: só o link mais recente vale. */
    void deleteByUserId(UUID userId);

    /** Exclusão de conta (LGPD). */
    @Modifying
    @Query("delete from PasswordResetToken t where t.userId = :userId")
    void purgeByUser(@Param("userId") UUID userId);

    @Modifying
    @Query("delete from PasswordResetToken t where t.expiresAt < :agora")
    void deleteExpired(@Param("agora") LocalDateTime agora);
}
