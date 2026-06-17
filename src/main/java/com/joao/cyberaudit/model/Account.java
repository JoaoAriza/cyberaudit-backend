package com.joao.cyberaudit.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NoArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "accounts")
@Getter @Setter
@Builder @NoArgsConstructor @AllArgsConstructor
public class Account {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AccountType type;

    @Builder.Default
    @Enumerated(EnumType.STRING)
    @Column(nullable = true)   // nullable para compatibilidade com linhas existentes; código trata null como FREE
    private Plan plan = Plan.FREE;

    @Column(nullable = false)
    private String displayName;

    private String companyName;
    private String companyDomain;
    private String companySize;

    private String fullName;
    private String profession;
    private String website;

    private String country;

    /** CNPJ (apenas dígitos, 14 chars). Preenchido apenas para contas COMPANY. */
    @Column(length = 14)
    private String cnpj;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    /** OWNER pode exigir que todos os usuários da conta configurem 2FA. */
    @Builder.Default
    @Column(nullable = false)
    private boolean require2fa = false;

    /**
     * Token único para a página de status pública.
     * Null = página desativada. Gerado pelo OWNER via AdminPanel.
     */
    @Column(unique = true, length = 64)
    private String publicStatusToken;
}
