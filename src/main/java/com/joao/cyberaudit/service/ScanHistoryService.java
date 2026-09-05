package com.joao.cyberaudit.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.ScanOrigin;
import com.joao.cyberaudit.model.ScanRecord;
import com.joao.cyberaudit.model.ScanResult;
import com.joao.cyberaudit.model.ScanSummary;
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

    // ── Listagens ────────────────────────────────────────────────────────────
    //
    // Todas devolvem ScanSummary, não ScanRecord: o laudo inteiro mora em
    // result_json e nenhuma delas o lê. Só getResult e findRecordById carregam a
    // entidade, porque ali o laudo É o objetivo.

    /**
     * Último resultado de um host DENTRO da conta — base da detecção de mudanças.
     * Escopado por conta: comparar contra o scan de outro tenant vazaria o estado
     * anterior daquela conta no diff.
     *
     * Roda em TODO scan, e era o pior caso da entidade: carregava dez laudos
     * completos para ler {@code activeMode} e um id, e então buscava o laudo de
     * novo pelo id. Agora os dez vêm como resumo e só o escolhido é lido.
     */
    public Optional<ScanResult> findLastResult(String host, boolean activeMode, Account account) {
        if (account == null) return Optional.empty();
        return findByHost(account, host, 10, null).stream()
                .filter(r -> r.isActiveMode() == activeMode)
                .findFirst()
                .flatMap(r -> getResult(r.getId(), account));
    }

    /** Scans de um host na conta, filtrando opcionalmente por origin. */
    public List<ScanSummary> findByHost(Account account, String host, int limit, ScanOrigin origin) {
        if (account == null) return List.of();
        String normalized = host.startsWith("www.") ? host.substring(4) : host;
        PageRequest page  = PageRequest.of(0, limit);
        List<ScanSummary> records = buscaPorHost(account, normalized, origin, page);
        // Fallback para registros legados gravados com www.
        if (records.isEmpty()) {
            records = buscaPorHost(account, "www." + normalized, origin, page);
        }
        return records;
    }

    private List<ScanSummary> buscaPorHost(Account account, String host,
                                           ScanOrigin origin, PageRequest page) {
        return (origin != null)
                ? repository.findSummariesByAccountAndHostAndOrigin(account, host, origin, page)
                : repository.findSummariesByAccountAndHost(account, host, page);
    }

    /**
     * Último scan de um host em QUALQUER conta. Uso restrito ao badge público, que
     * expõe só score e nível de risco do alvo — nunca para devolver histórico a um
     * usuário. Todo o resto passa pelas variantes com Account.
     */
    public List<ScanSummary> findLatestForBadge(String host) {
        String normalized = host.startsWith("www.") ? host.substring(4) : host;
        PageRequest page  = PageRequest.of(0, 1);
        List<ScanSummary> records = repository.findSummariesByHost(normalized, page);
        if (records.isEmpty()) {
            records = repository.findSummariesByHost("www." + normalized, page);
        }
        return records;
    }

    /** Último scan por host para uma conta (para Visão Geral). */
    public List<ScanSummary> findLatestPerHost(Account account, int limit) {
        if (account == null) return List.of();
        return repository.findLatestSummaryPerHostByAccount(account, PageRequest.of(0, limit));
    }

    /** Scans de um host da conta em um intervalo de datas (para gráfico intraday). */
    public List<ScanSummary> findByHostBetween(Account account, String host,
                                               LocalDateTime from, LocalDateTime to) {
        if (account == null) return List.of();
        String normalized = host.startsWith("www.") ? host.substring(4) : host;
        PageRequest page  = PageRequest.of(0, 200);
        List<ScanSummary> records = repository
                .findSummariesByAccountAndHostBetween(account, normalized, from, to, page);
        if (records.isEmpty()) {
            records = repository.findSummariesByAccountAndHostBetween(
                    account, "www." + normalized, from, to, page);
        }
        return records;
    }

    public List<ScanSummary> findRecent(Account account, int limit) {
        if (account == null) return List.of();
        return repository.findSummariesByAccount(account, PageRequest.of(0, limit));
    }

    public List<ScanSummary> findRecentByOrigin(Account account, int limit, ScanOrigin origin) {
        if (account == null) return List.of();
        return repository.findSummariesByAccountAndOrigin(
                account, origin, PageRequest.of(0, limit));
    }

    /**
     * Resultado completo de um scan, apenas se ele pertencer à conta informada.
     * Sem esse filtro, qualquer usuário autenticado lê o scan de qualquer conta
     * conhecendo o UUID.
     */
    public Optional<ScanResult> getResult(UUID id, Account account) {
        if (account == null) return Optional.empty();
        return repository.findById(id)
                .filter(r -> r.getAccount() != null
                        && r.getAccount().getId().equals(account.getId()))
                .flatMap(r -> {
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
