package com.joao.cyberaudit.service;

import com.joao.cyberaudit.repository.AuditLogRepository;
import com.joao.cyberaudit.repository.GuestScanLimitRepository;
import com.joao.cyberaudit.repository.ScanRecordRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalDateTime;

/**
 * LGPD — Política de retenção de dados.
 * Remove automaticamente dados antigos conforme os prazos configurados.
 */
@Service
public class DataRetentionService {

    private final ScanRecordRepository    scanRecordRepository;
    private final GuestScanLimitRepository guestScanLimitRepository;
    private final AuditLogRepository      auditLogRepository;

    /** Manter scan_records por X dias (padrão: 365). -1 = nunca deletar. */
    @Value("${data.retention.scan-records-days:365}")
    private int scanRetentionDays;

    /** Manter guest_daily_scans por X dias (padrão: 30). -1 = nunca deletar. */
    @Value("${data.retention.guest-scans-days:30}")
    private int guestRetentionDays;

    /** Manter audit_logs por X dias (padrão: 365). -1 = nunca deletar. */
    @Value("${data.retention.audit-logs-days:365}")
    private int auditLogRetentionDays;

    public DataRetentionService(ScanRecordRepository scanRecordRepository,
                                GuestScanLimitRepository guestScanLimitRepository,
                                AuditLogRepository auditLogRepository) {
        this.scanRecordRepository   = scanRecordRepository;
        this.guestScanLimitRepository = guestScanLimitRepository;
        this.auditLogRepository     = auditLogRepository;
    }

    /**
     * Executa toda madrugada às 03:00.
     * Remove scan_records e guest_daily_scans fora do prazo de retenção.
     */
    @Scheduled(cron = "0 0 3 * * *")
    @Transactional
    public void runRetention() {
        int totalDeleted = 0;

        if (scanRetentionDays > 0) {
            LocalDateTime scanCutoff = LocalDateTime.now().minusDays(scanRetentionDays);
            int deleted = scanRecordRepository.deleteByScannedAtBefore(scanCutoff);
            totalDeleted += deleted;
            if (deleted > 0) {
                System.out.printf("[DataRetention] scan_records: %d registros removidos (> %d dias)%n",
                        deleted, scanRetentionDays);
            }
        }

        if (guestRetentionDays > 0) {
            LocalDate guestCutoff = LocalDate.now().minusDays(guestRetentionDays);
            int deleted = guestScanLimitRepository.deleteByIdScanDateBefore(guestCutoff);
            totalDeleted += deleted;
            if (deleted > 0) {
                System.out.printf("[DataRetention] guest_daily_scans: %d registros removidos (> %d dias)%n",
                        deleted, guestRetentionDays);
            }
        }

        if (auditLogRetentionDays > 0) {
            LocalDateTime auditCutoff = LocalDateTime.now().minusDays(auditLogRetentionDays);
            int deleted = auditLogRepository.deleteByTimestampBefore(auditCutoff);
            totalDeleted += deleted;
            if (deleted > 0) {
                System.out.printf("[DataRetention] audit_logs: %d registros removidos (> %d dias)%n",
                        deleted, auditLogRetentionDays);
            }
        }

        if (totalDeleted > 0) {
            System.out.printf("[DataRetention] Total removido: %d registros%n", totalDeleted);
        }
    }
}
