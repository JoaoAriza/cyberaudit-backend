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
@Table(name = "invites")
@Getter @Setter
@Builder @NoArgsConstructor @AllArgsConstructor
public class Invite {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /** Nome do convidado — pré-preenchido na tela de aceite */
    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String email;

    /** Token único enviado no link de aceite */
    @Column(unique = true, nullable = false)
    private String token;

    /** Role que o usuário receberá ao aceitar */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role;

    /** Cargo opcional — pré-preenchido na tela de aceite */
    private String jobTitle;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "invited_by", nullable = false)
    private AppUser invitedBy;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "account_id")
    private Account account;

    private boolean accepted;

    /** Expira em 48h — convites antigos são limpos automaticamente */
    @Column(nullable = false)
    private LocalDateTime expiresAt;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    private LocalDateTime acceptedAt;

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiresAt);
    }
}