package com.joao.cyberaudit.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "domains", uniqueConstraints = {
        @UniqueConstraint(columnNames = {"account_id", "host"})
})
@Getter @Setter
@Builder @NoArgsConstructor @AllArgsConstructor
public class Domain {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "account_id", nullable = false)
    private Account account;

    /** Hostname normalizado — sem protocolo, sem path, sem trailing slash */
    @Column(nullable = false, length = 253)
    private String host;

    @Builder.Default
    private boolean verified = false;

    private LocalDateTime verifiedAt;

    @Column(nullable = false)
    private LocalDateTime createdAt;
}
