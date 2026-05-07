package com.joao.cyberaudit.repository;

import com.joao.cyberaudit.model.ScanRecord;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface ScanRecordRepository extends JpaRepository<ScanRecord, UUID> {

    List<ScanRecord> findByHostOrderByScannedAtDesc(String host, Pageable pageable);

    List<ScanRecord> findAllByOrderByScannedAtDesc(Pageable pageable);

    boolean existsByHostAndScannedAtAfter(String host,
                                          java.time.LocalDateTime after);
}