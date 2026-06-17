package com.joao.cyberaudit.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NoArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Armazena códigos OTP de email (6 dígitos, uso único, expiram em 10 min).
 * Não é usado para TOTP — o segredo TOTP fica no AppUser.
 */
@Entity
@Table(name = "otp_codes", indexes = {
        @Index(name = "idx_otp_user_id", columnList = "user_id")
})
@Getter @Setter
@Builder @NoArgsConstructor @AllArgsConstructor
public class OtpCode {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "user_id", nullable = false)
    private UUID userId;

    @Column(nullable = false, length = 6)
    private String code;

    @Column(nullable = false)
    private LocalDateTime expiresAt;

    @Builder.Default
    @Column(nullable = false)
    private boolean used = false;

    @Column(nullable = false)
    private LocalDateTime createdAt;
}
