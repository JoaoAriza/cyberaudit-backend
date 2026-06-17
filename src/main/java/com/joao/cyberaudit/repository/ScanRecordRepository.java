package com.joao.cyberaudit.repository;

import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.ScanRecord;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Repository
public interface ScanRecordRepository extends JpaRepository<ScanRecord, UUID> {

    List<ScanRecord> findByHostOrderByScannedAtDesc(String host, Pageable pageable);

    List<ScanRecord> findAllByOrderByScannedAtDesc(Pageable pageable);

    boolean existsByHostAndScannedAtAfter(String host, LocalDateTime after);

    /** Retenção de dados: remove registros mais antigos que a data de corte. */
    @Modifying
    @Query("DELETE FROM ScanRecord s WHERE s.scannedAt < :cutoff")
    int deleteByScannedAtBefore(LocalDateTime cutoff);

    /**
     * Retorna o scan mais recente de cada host associado à conta.
     * Usado para o relatório executivo quando não há domínios registrados.
     */
    @Query("""
        SELECT s FROM ScanRecord s
        WHERE s.account = :account
          AND s.scannedAt = (
              SELECT MAX(s2.scannedAt) FROM ScanRecord s2
              WHERE s2.account = :account AND s2.host = s.host
          )
        ORDER BY s.scannedAt DESC
        """)
    List<ScanRecord> findLatestPerHostByAccount(@Param("account") Account account, Pageable pageable);
}