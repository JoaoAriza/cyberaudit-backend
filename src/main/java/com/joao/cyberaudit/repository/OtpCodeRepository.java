package com.joao.cyberaudit.repository;

import com.joao.cyberaudit.model.OtpCode;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface OtpCodeRepository extends JpaRepository<OtpCode, UUID> {

    /** Busca código válido (não usado, não expirado) para o usuário. */
    Optional<OtpCode> findFirstByUserIdAndCodeAndUsedFalseAndExpiresAtAfterOrderByCreatedAtDesc(
            UUID userId, String code, LocalDateTime now);

    /** Remove todos os OTPs do usuário (ao desativar email OTP ou ao validar). */
    @Modifying
    @Query("DELETE FROM OtpCode o WHERE o.userId = :userId")
    void deleteByUserId(UUID userId);

    /** Limpeza periódica de códigos expirados. */
    @Modifying
    @Query("DELETE FROM OtpCode o WHERE o.expiresAt < :now")
    void deleteExpired(LocalDateTime now);
}
