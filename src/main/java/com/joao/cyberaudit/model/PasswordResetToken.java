package com.joao.cyberaudit.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Token de redefinição de senha.
 *
 * <h2>Por que guarda hash e não o token</h2>
 *
 * Este token vale tanto quanto a senha: quem o tiver troca a senha da conta. Se
 * ficasse em claro, um vazamento de banco (ou um backup, ou um dump de suporte)
 * entregaria acesso a todas as contas com redefinição pendente — sem precisar
 * quebrar nenhum bcrypt. Guardando o SHA-256, o que vaza não serve para nada: o
 * valor original só existiu no e-mail do dono.
 *
 * SHA-256 puro basta aqui, diferente de senha: o token tem 256 bits de entropia
 * aleatória, então não há dicionário nem força bruta viável — o custo do bcrypt
 * protegeria contra um ataque que não existe neste caso.
 */
@Entity
@Table(name = "password_reset_tokens", indexes = {
        @Index(name = "idx_prt_token_hash", columnList = "token_hash"),
        @Index(name = "idx_prt_user", columnList = "user_id")
})
@Getter @Setter
@Builder @NoArgsConstructor @AllArgsConstructor
public class PasswordResetToken {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "user_id", nullable = false)
    private UUID userId;

    /** SHA-256 do token, em hexadecimal. Nunca o token em si. */
    @Column(name = "token_hash", nullable = false, length = 64)
    private String tokenHash;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @Column(nullable = false)
    @Builder.Default
    private boolean used = false;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;
}
