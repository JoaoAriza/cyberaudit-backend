package com.joao.cyberaudit.repository;

import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.ScheduledScan;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

public interface ScheduledScanRepository extends JpaRepository<ScheduledScan, UUID> {

    List<ScheduledScan> findByUserOrderByCreatedAtDesc(AppUser user);

    void deleteByUser(AppUser user);

    /**
     * Todos os agendamentos habilitados com nextRun <= agora (prontos para executar).
     * JOIN FETCH garante que user.account é carregado imediatamente — evita
     * LazyInitializationException quando o executor sai do contexto transacional.
     */
    @Query("SELECT s FROM ScheduledScan s JOIN FETCH s.user u JOIN FETCH u.account WHERE s.enabled = true AND s.nextRun <= :now")
    List<ScheduledScan> findDue(@Param("now") LocalDateTime now);
}
