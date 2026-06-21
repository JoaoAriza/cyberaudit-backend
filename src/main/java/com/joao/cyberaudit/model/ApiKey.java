package com.joao.cyberaudit.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * API Key para acesso programático / CI-CD.
 *
 * A chave completa nunca é armazenada — apenas o hash BCrypt (keyHash)
 * e os 8 primeiros caracteres (keyPrefix) para exibição na UI.
 * O valor completo é retornado apenas uma vez, no momento da geração.
 *
 * Formato da chave: ca_<32 hex chars>   (ex: ca_a3f9b2...)
 */
@Entity
@Table(name = "api_keys")
@Getter @Setter @Builder @NoArgsConstructor @AllArgsConstructor
public class ApiKey {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /** Nome descritivo dado pelo usuário (ex: "GitHub CI", "Deploy Pipeline") */
    @Column(nullable = false, length = 100)
    private String name;

    /** Prefixo para exibição — primeiros 8 chars após "ca_" */
    @Column(nullable = false, length = 16)
    private String keyPrefix;

    /** Hash BCrypt da chave completa */
    @Column(nullable = false)
    private String keyHash;

    /** Conta à qual esta key pertence */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "account_id", nullable = false)
    private Account account;

    /** Usuário que gerou a key */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "created_by")
    private AppUser createdBy;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    /** Atualizado a cada uso bem-sucedido */
    private LocalDateTime lastUsedAt;

    /** Null = ativa. Preenchida quando revogada. */
    private LocalDateTime revokedAt;

    /** Expiração opcional. Null = sem expiração. */
    private LocalDateTime expiresAt;

    /** @return true se a key está ativa e não expirou */
    public boolean isActive() {
        if (revokedAt != null) return false;
        if (expiresAt != null && LocalDateTime.now().isAfter(expiresAt)) return false;
        return true;
    }
}
