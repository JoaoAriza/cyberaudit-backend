package com.joao.cyberaudit.repository;

import com.joao.cyberaudit.model.GuestScanLimit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.util.Optional;

@Repository
public interface GuestScanLimitRepository
        extends JpaRepository<GuestScanLimit, GuestScanLimit.GuestScanLimitId> {

    Optional<GuestScanLimit> findByIdIpAndIdScanDate(String ip, LocalDate date);

    /** Retenção: remove registros de scan de guests anteriores à data de corte. */
    @org.springframework.data.jpa.repository.Modifying
    @org.springframework.data.jpa.repository.Query("DELETE FROM GuestScanLimit g WHERE g.id.scanDate < :cutoff")
    int deleteByIdScanDateBefore(LocalDate cutoff);
}