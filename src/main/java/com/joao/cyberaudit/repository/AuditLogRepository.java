package com.joao.cyberaudit.repository;

import com.joao.cyberaudit.model.AuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, UUID> {

    Page<AuditLog> findByAccountIdOrderByTimestampDesc(UUID accountId, Pageable pageable);

    Page<AuditLog> findByAccountIdAndTimestampBetweenOrderByTimestampDesc(
            UUID accountId, LocalDateTime from, LocalDateTime to, Pageable pageable);

    /** Busca eventos de scan concluído por conta dentro de um intervalo. */
    @Query("""
        SELECT a FROM AuditLog a
        WHERE a.accountId = :accountId
          AND a.action = :action
          AND a.timestamp >= :from
          AND a.timestamp <= :to
        ORDER BY a.timestamp DESC
        """)
    List<AuditLog> findScanCompletedByAccountBetween(
            @Param("accountId") UUID accountId,
            @Param("action") com.joao.cyberaudit.model.AuditAction action,
            @Param("from") LocalDateTime from,
            @Param("to") LocalDateTime to);

    /** Para PDF: todos os eventos da conta (até 500), sem filtro de data. */
    List<AuditLog> findTop500ByAccountIdOrderByTimestampDesc(UUID accountId);

    /** Para PDF: todos os eventos da conta (até 500), filtrado por período. */
    List<AuditLog> findTop500ByAccountIdAndTimestampBetweenOrderByTimestampDesc(
            UUID accountId, LocalDateTime from, LocalDateTime to);

    @Modifying
    @Transactional
    @Query("DELETE FROM AuditLog a WHERE a.timestamp < :cutoff")
    int deleteByTimestampBefore(LocalDateTime cutoff);
}
