package com.joao.cyberaudit.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.joao.cyberaudit.model.ScanRecord;
import com.joao.cyberaudit.model.ScanResult;
import com.joao.cyberaudit.repository.ScanRecordRepository;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class ScanHistoryService {

    private final ScanRecordRepository repository;
    private final ObjectMapper         objectMapper;

    public ScanHistoryService(ScanRecordRepository repository, ObjectMapper objectMapper) {
        this.repository   = repository;
        this.objectMapper = objectMapper;
    }

    public void save(ScanResult result) {
        try {
            String host = extractHost(result.getFinalUrl() != null
                    ? result.getFinalUrl() : result.getUrl());
            String json = objectMapper.writeValueAsString(result);
            ScanRecord record = ScanRecord.builder()
                    .url(result.getUrl())
                    .host(host)
                    .scannedAt(LocalDateTime.now())
                    .activeMode(result.isActiveMode())
                    .score(result.getScore().getScore())
                    .riskLevel(result.getScore().getRiskLevel())
                    .resultJson(json)
                    .build();
            repository.save(record);
        } catch (Exception e) {
            System.err.println("[ScanHistoryService] Falha ao persistir scan: " + e.getMessage());
        }
    }

    /**
     * Retorna o resultado do scan mais recente para um host no mesmo modo (ativo/passivo).
     * Usado pelo ScanChangeDetector para comparar com o scan atual.
     *
     * Busca os 10 scans mais recentes e filtra por activeMode em memória —
     * evita adicionar método ao repository.
     */
    public Optional<ScanResult> findLastResult(String host, boolean activeMode) {
        return findByHost(host, 10).stream()
                .filter(r -> r.isActiveMode() == activeMode)
                .findFirst()
                .flatMap(r -> getResult(r.getId()));
    }

    public List<ScanRecord> findByHost(String host, int limit) {
        return repository.findByHostOrderByScannedAtDesc(host, PageRequest.of(0, limit));
    }

    public List<ScanRecord> findRecent(int limit) {
        return repository.findAllByOrderByScannedAtDesc(PageRequest.of(0, limit));
    }

    public Optional<ScanRecord> findById(UUID id) {
        return repository.findById(id);
    }

    public Optional<ScanResult> getResult(UUID id) {
        return findById(id).flatMap(record -> {
            try {
                return Optional.of(objectMapper.readValue(record.getResultJson(), ScanResult.class));
            } catch (Exception e) {
                return Optional.empty();
            }
        });
    }

    private String extractHost(String url) {
        try { return URI.create(url).getHost(); }
        catch (Exception e) { return url; }
    }
}