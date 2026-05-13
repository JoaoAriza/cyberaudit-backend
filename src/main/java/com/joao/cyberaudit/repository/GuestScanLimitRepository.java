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
}