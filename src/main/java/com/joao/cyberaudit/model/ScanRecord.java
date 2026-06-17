package com.joao.cyberaudit.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "scan_records", indexes = {
        @Index(name = "idx_scan_host", columnList = "host"),
        @Index(name = "idx_scan_scanned_at", columnList = "scanned_at")
})
@Getter @Setter @Builder @NoArgsConstructor @AllArgsConstructor
public class ScanRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false)
    private String url;

    @Column(nullable = false)
    private String host;

    @Column(name = "scanned_at", nullable = false)
    private LocalDateTime scannedAt;

    private boolean activeMode;

    private int score;

    @Enumerated(EnumType.STRING)
    private RiskLevel riskLevel;

    @Column(columnDefinition = "TEXT", nullable = false)
    private String resultJson;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "account_id")
    private Account account;
}
