package com.joao.cyberaudit.repository;

import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.ScanOrigin;
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

    // ── Por host ─────────────────────────────────────────────────────────────

    List<ScanRecord> findByHostOrderByScannedAtDesc(String host, Pageable pageable);

    List<ScanRecord> findByHostAndOriginOrderByScannedAtDesc(String host, ScanOrigin origin, Pageable pageable);

    List<ScanRecord> findByHostAndScannedAtBetweenOrderByScannedAtDesc(
            String host, LocalDateTime from, LocalDateTime to, Pageable pageable);

    // ── Globais (sem filtro de conta) ─────────────────────────────────────────
    // ATENÇÃO: só para uso público que não expõe dados da conta — hoje apenas o
    // badge (score + nível de risco de um host). Tudo que devolve histórico a um
    // usuário DEVE usar as variantes por conta abaixo.

    List<ScanRecord> findAllByOrderByScannedAtDesc(Pageable pageable);

    List<ScanRecord> findAllByOriginOrderByScannedAtDesc(ScanOrigin origin, Pageable pageable);

    // ── Escopados por conta (histórico do usuário) ────────────────────────────

    List<ScanRecord> findByAccountOrderByScannedAtDesc(Account account, Pageable pageable);

    List<ScanRecord> findByAccountAndOriginOrderByScannedAtDesc(
            Account account, ScanOrigin origin, Pageable pageable);

    List<ScanRecord> findByAccountAndHostOrderByScannedAtDesc(
            Account account, String host, Pageable pageable);

    List<ScanRecord> findByAccountAndHostAndOriginOrderByScannedAtDesc(
            Account account, String host, ScanOrigin origin, Pageable pageable);

    List<ScanRecord> findByAccountAndHostAndScannedAtBetweenOrderByScannedAtDesc(
            Account account, String host, LocalDateTime from, LocalDateTime to, Pageable pageable);

    // ── Por conta (TEAM_SCANS / PDF executivo) ────────────────────────────────

    /** Último scan por host distinto para uma conta (sem filtro de data). */
    @Query("""
            SELECT r FROM ScanRecord r
            WHERE r.account = :account
              AND r.scannedAt = (
                  SELECT MAX(r2.scannedAt) FROM ScanRecord r2
                  WHERE r2.account = :account AND r2.host = r.host)
            ORDER BY r.scannedAt DESC
            """)
    List<ScanRecord> findLatestPerHostByAccount(@Param("account") Account account, Pageable pageable);

    /** Último scan por host distinto para uma conta dentro de um intervalo. */
    @Query("""
            SELECT r FROM ScanRecord r
            WHERE r.account = :account
              AND r.scannedAt BETWEEN :from AND :to
              AND r.scannedAt = (
                  SELECT MAX(r2.scannedAt) FROM ScanRecord r2
                  WHERE r2.account = :account AND r2.host = r.host
                    AND r2.scannedAt BETWEEN :from AND :to)
            ORDER BY r.scannedAt DESC
            """)
    List<ScanRecord> findLatestPerHostByAccountBetween(
            @Param("account") Account account,
            @Param("from") LocalDateTime from,
            @Param("to") LocalDateTime to,
            Pageable pageable);

    // ── Existência ────────────────────────────────────────────────────────────

    boolean existsByHostAndScannedAtAfter(String host, LocalDateTime after);

    // ── Retenção de dados ─────────────────────────────────────────────────────

    /** Remove registros antigos de uma conta (retenção por plano). */
    @Modifying
    @Query("DELETE FROM ScanRecord r WHERE r.scannedAt < :cutoff AND r.account = :account")
    int deleteOlderThan(@Param("cutoff") LocalDateTime cutoff, @Param("account") Account account);

    /** Remove registros mais antigos que o corte global (sem filtro de conta). */
    @Modifying
    @Query("DELETE FROM ScanRecord r WHERE r.scannedAt < :cutoff")
    int deleteByScannedAtBefore(@Param("cutoff") LocalDateTime cutoff);

    /**
     * Exclusão de conta (LGPD, direito ao esquecimento): remove o histórico de scans.
     * Sem isto, a FK scan_records.account_id impedia a exclusão da conta — e, como
     * todo scan autenticado grava um registro aqui, isso significava que nenhuma
     * conta que já tivesse usado o produto conseguia ser excluída.
     */
    @Modifying
    @Query("DELETE FROM ScanRecord r WHERE r.account = :account")
    int deleteByAccount(@Param("account") Account account);
}
