package com.joao.cyberaudit.repository;

import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.ScanOrigin;
import com.joao.cyberaudit.model.ScanRecord;
import com.joao.cyberaudit.model.ScanSummary;
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

    /**
     * Projeção das listagens: monta o {@link ScanSummary} no próprio SELECT.
     *
     * O laudo inteiro de um scan mora em {@code result_json}, uma coluna TEXT que
     * o Postgres guarda fora da linha (TOAST). Devolver a entidade numa listagem
     * traz esse blob junto para cada registro — 50 laudos completos lidos do disco
     * para desenhar 50 linhas com host, data e score. Nas listagens ele nunca é
     * lido; só {@code getResult} e o PDF executivo precisam dele, e esses
     * continuam usando a entidade.
     *
     * Constante de interface porque anotação exige constante de compilação — é o
     * que permite escrever o SELECT uma vez em vez de repeti-lo em cada consulta.
     */
    String SUMMARY = """
            SELECT new com.joao.cyberaudit.model.ScanSummary(
                       r.id, r.url, r.host, r.scannedAt,
                       r.activeMode, r.score, r.riskLevel, r.origin)
            FROM ScanRecord r
            """;

    // ── Listagens (sem o laudo) ──────────────────────────────────────────────

    @Query(SUMMARY + "WHERE r.account = :account ORDER BY r.scannedAt DESC")
    List<ScanSummary> findSummariesByAccount(@Param("account") Account account, Pageable pageable);

    @Query(SUMMARY + "WHERE r.account = :account AND r.origin = :origin ORDER BY r.scannedAt DESC")
    List<ScanSummary> findSummariesByAccountAndOrigin(
            @Param("account") Account account, @Param("origin") ScanOrigin origin, Pageable pageable);

    @Query(SUMMARY + "WHERE r.account = :account AND r.host = :host ORDER BY r.scannedAt DESC")
    List<ScanSummary> findSummariesByAccountAndHost(
            @Param("account") Account account, @Param("host") String host, Pageable pageable);

    @Query(SUMMARY + """
            WHERE r.account = :account AND r.host = :host AND r.origin = :origin
            ORDER BY r.scannedAt DESC
            """)
    List<ScanSummary> findSummariesByAccountAndHostAndOrigin(
            @Param("account") Account account, @Param("host") String host,
            @Param("origin") ScanOrigin origin, Pageable pageable);

    @Query(SUMMARY + """
            WHERE r.account = :account AND r.host = :host
              AND r.scannedAt BETWEEN :from AND :to
            ORDER BY r.scannedAt DESC
            """)
    List<ScanSummary> findSummariesByAccountAndHostBetween(
            @Param("account") Account account, @Param("host") String host,
            @Param("from") LocalDateTime from, @Param("to") LocalDateTime to, Pageable pageable);

    /** Badge público: só o score e o nível de risco do host, sem escopo de conta. */
    @Query(SUMMARY + "WHERE r.host = :host ORDER BY r.scannedAt DESC")
    List<ScanSummary> findSummariesByHost(@Param("host") String host, Pageable pageable);

    /** Visão Geral: último scan por host distinto da conta, só o resumo. */
    @Query(SUMMARY + """
            WHERE r.account = :account
              AND r.scannedAt = (
                  SELECT MAX(r2.scannedAt) FROM ScanRecord r2
                  WHERE r2.account = :account AND r2.host = r.host)
            ORDER BY r.scannedAt DESC
            """)
    List<ScanSummary> findLatestSummaryPerHostByAccount(
            @Param("account") Account account, Pageable pageable);

    // ── Por host ─────────────────────────────────────────────────────────────

    List<ScanRecord> findByHostOrderByScannedAtDesc(String host, Pageable pageable);

    List<ScanRecord> findByHostAndOriginOrderByScannedAtDesc(String host, ScanOrigin origin, Pageable pageable);

    List<ScanRecord> findByHostAndScannedAtBetweenOrderByScannedAtDesc(
            String host, LocalDateTime from, LocalDateTime to, Pageable pageable);

    // ── Por conta (TEAM_SCANS / PDF executivo) ────────────────────────────────
    //
    // ATENÇÃO: as consultas por host acima não filtram por conta. Uso restrito ao
    // que é público por natureza — o badge, que expõe só score e nível de risco —
    // e ao PDF executivo, que já resolveu o escopo antes de chegar aqui. Tudo que
    // devolve histórico a um usuário passa pelas variantes com Account.

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
