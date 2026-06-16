package com.joao.cyberaudit.repository;

import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.ScheduledScan;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

public interface ScheduledScanRepository extends JpaRepository<ScheduledScan, UUID> {

    List<ScheduledScan> findByUserOrderByCreatedAtDesc(AppUser user);

    /** Todos os agendamentos habilitados com nextRun <= agora (prontos para executar) */
    @Query("SELECT s FROM ScheduledScan s WHERE s.enabled = true AND s.nextRun <= :now")
    List<ScheduledScan> findDue(@Param("now") LocalDateTime now);

    /** Exclusão de conta: remove todos os agendamentos do usuário. */
    @Modifying
    @Query("DELETE FROM ScheduledScan s WHERE s.user = :user")
    void deleteByUser(@Param("user") AppUser user);
}
