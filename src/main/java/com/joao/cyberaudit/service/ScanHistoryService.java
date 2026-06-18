package com.joao.cyberaudit.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.ScanOrigin;
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
        save(result, null, ScanOrigin.MANUAL);
    }

    public void save(ScanResult result, Account account) {
        save(result, account, ScanOrigin.MANUAL);
    }

    public void save(ScanResult result, Account account, ScanOrigin origin) {
        try {
            String rawHost = extractHost(result.getFinalUrl() != null
                    ? result.getFinalUrl() : result.getUrl());
            // Normaliza: remove www. — queries sempre usam o domínio raiz
            String host = (rawHost != null && rawHost.startsWith("www."))
                    ? rawHost.substring(4) : rawHost;
            if (host == null || host.isBlank()) {
                System.err.println("[ScanHistoryService] Host nulo, ignorando save para: " + result.getUrl());
                return;
            }
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
                    .origin(origin)
                    .build();
            repository.save(record);
        } catch (Exception e) {
            System.err.println("[ScanHistoryService] Falha ao persistir scan: " + e.getMessage());
        }
    }

    public Optional<ScanResult> findLastResult(String host, boolean activeMode) {
        return findByHost(host, 10, null).stream()
                .filter(r -> r.isActiveMode() == activeMode)
                .findFirst()
                .flatMap(r -> getResult(r.getId()));
    }

    /** Busca scans de um host, filtrando opcionalmente por origin. */
    public List<ScanRecord> findByHost(String host, int limit, ScanOrigin origin) {
        String normalized = host.startsWith("www.") ? host.substring(4) : host;
        PageRequest page  = PageRequest.of(0, limit);
        List<ScanRecord> records = (origin != null)
                ? repository.findByHostAndOriginOrderByScannedAtDesc(normalized, origin, page)
                : repository.findByHostOrderByScannedAtDesc(normalized, page);
        // Fallback para registros legados gravados com www.
        if (records.isEmpty()) {
            records = (origin != null)
                    ? repository.findByHostAndOriginOrderByScannedAtDesc("www." + normalized, origin, page)
                    : repository.findByHostOrderByScannedAtDesc("www." + normalized, page);
        }
        return records;
    }

    /** Compatibilidade — sem filtro de origin. */
    public List<ScanRecord> findByHost(String host, int limit) {
        return findByHost(host, limit, null);
    }

    /** Último scan por host para uma conta (para Visão Geral). */
    public List<ScanRecord> findLatestPerHost(Account account, int limit) {
        return repository.findLatestPerHostByAccount(account, PageRequest.of(0, limit));
    }

    /** Busca scans de um host em um intervalo de datas (para gráfico intraday). */
    public List<ScanRecord> findByHostBetween(String host, LocalDateTime from, LocalDateTime to) {
        String normalized = host.startsWith("www.") ? host.substring(4) : host;
        PageRequest page  = PageRequest.of(0, 200);
        List<ScanRecord> records = repository.findByHostAndScannedAtBetweenOrderByScannedAtDesc(normalized, from, to, page);
        if (records.isEmpty()) {
            records = repository.findByHostAndScannedAtBetweenOrderByScannedAtDesc("www." + normalized, from, to, page);
        }
        return records;
    }

    public List<ScanRecord> findRecent(int limit) {
        return repository.findAllByOrderByScannedAtDesc(PageRequest.of(0, limit));
    }

    public List<ScanRecord> findRecentByOrigin(int limit, ScanOrigin origin) {
        return repository.findAllByOriginOrderByScannedAtDesc(origin, PageRequest.of(0, limit));
    }

    public Optional<ScanResult> getResult(UUID id) {
        return repository.findById(id).flatMap(r -> {
            try {
                return Optional.of(objectMapper.readValue(r.getResultJson(), ScanResult.class));
            } catch (Exception e) {
                System.err.println("[ScanHistoryService] Falha ao desserializar scan " + id + ": " + e.getMessage());
                return Optional.empty();
            }
        });
    }

    public Optional<ScanRecord> findRecordById(UUID id) {
        return repository.findById(id);
    }

    private String extractHost(String url) {
        if (url == null || url.isBlank()) return null;
        try {
            String h = URI.create(url).getHost();
            return (h != null && !h.isBlank()) ? h : null;
        } catch (Exception e) {
            return null;
        }
    }
}
