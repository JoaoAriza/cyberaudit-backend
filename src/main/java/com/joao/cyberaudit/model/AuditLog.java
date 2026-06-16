package com.joao.cyberaudit.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "audit_logs", indexes = {
        @Index(name = "idx_audit_account", columnList = "account_id"),
        @Index(name = "idx_audit_timestamp", columnList = "timestamp")
})
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /** Conta associada — null para ações antes do login completo. */
    @Column(name = "account_id")
    private UUID accountId;

    /** Usuário que realizou a ação — null em falhas de login (usuário pode não existir). */
    @Column(name = "user_id")
    private UUID userId;

    /** Email armazenado diretamente — persiste mesmo após exclusão do usuário. */
    @Column(name = "user_email", length = 255)
    private String userEmail;

    @Column(name = "user_name", length = 255)
    private String userName;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 50)
    private AuditAction action;

    /** Contexto adicional (ex: "role alterado para ADMIN", "domínio: example.com"). */
    @Column(length = 500)
    private String details;

    @Column(name = "ip_address", length = 100)
    private String ipAddress;

    @Column(nullable = false)
    private LocalDateTime timestamp;

    @Column(nullable = false)
    @Builder.Default
    private boolean success = true;
}
