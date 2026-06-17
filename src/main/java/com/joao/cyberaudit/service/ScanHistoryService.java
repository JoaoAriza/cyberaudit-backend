package com.joao.cyberaudit.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.joao.cyberaudit.model.Account;
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

    /** Salva sem conta associada (scans anônimos/guest). */
    public void save(ScanResult result) {
        save(result, null);
    }

    /** Salva com conta associada — permite relatório executivo por conta. */
    public void save(ScanResult result, Account account) {
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
                    .account(account)
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
        // Normaliza: remove www. para busca primária
        String normalized = host.startsWith("www.") ? host.substring(4) : host;
        List<ScanRecord> records = repository.findByHostOrderByScannedAtDesc(
                normalized, PageRequest.of(0, limit));
        // Fallback para registros legados gravados com www.
        if (records.isEmpty() && !host.startsWith("www.")) {
            records = repository.findByHostOrderByScannedAtDesc(
                    "www." + normalized, PageRequest.of(0, limit));
        }
        return records;
    }

    public List<ScanRecord> findRecent(int limit) {
        return repository.findAllByOrderByScannedAtDesc(PageRequest.of(0, limit));
    }

    /** Retorna os scans mais recentes de uma conta (apenas o mais recente por host). */
    public List<ScanRecord> findRecentByAccount(Account account, int limit) {
        return repository.findLatestPerHostByAccount(account, PageRequest.of(0, limit));
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

    /**
     * Extrai e normaliza o host de uma URL.
     * Remove o prefixo "www." para garantir consistência com os hosts registrados
     * em Domain (que o usuário normalmente cadastra sem "www.").
     * Ex: "https://www.example.com/path" → "example.com"
     */
    private String extractHost(String url) {
        try {
            String h = URI.create(url).getHost();
            if (h == null) return url;
            return h.startsWith("www.") ? h.substring(4) : h;
        } catch (Exception e) {
            return url;
        }
    }
}