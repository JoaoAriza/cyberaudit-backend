package com.joao.cyberaudit.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.joao.cyberaudit.dto.PublicStatusDto;
import com.joao.cyberaudit.model.*;
import com.joao.cyberaudit.repository.AccountRepository;
import com.joao.cyberaudit.repository.DomainRepository;
import com.joao.cyberaudit.repository.ScanRecordRepository;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/public/status")
public class PublicStatusController {

    private static final DateTimeFormatter FMT =
            DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm");

    private final AccountRepository    accountRepository;
    private final DomainRepository     domainRepository;
    private final ScanRecordRepository scanRecordRepository;
    private final ObjectMapper         objectMapper;

    public PublicStatusController(AccountRepository accountRepository,
                                  DomainRepository domainRepository,
                                  ScanRecordRepository scanRecordRepository,
                                  ObjectMapper objectMapper) {
        this.accountRepository    = accountRepository;
        this.domainRepository     = domainRepository;
        this.scanRecordRepository = scanRecordRepository;
        this.objectMapper         = objectMapper;
    }

    /**
     * Retorna a página de status pública da conta identificada pelo token.
     * Não requer autenticação — protegido apenas pelo token opaco.
     */
    @GetMapping("/{token}")
    public ResponseEntity<PublicStatusDto> getStatus(@PathVariable String token) {
        Account account = accountRepository.findByPublicStatusToken(token)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Página de status não encontrada."));

        List<Domain> domains = domainRepository.findByAccountOrderByCreatedAtDesc(account);

        List<PublicStatusDto.DomainStatusDto> domainDtos = domains.stream()
                .map(this::buildDomainStatus)
                .collect(Collectors.toList());

        // Aggregate stats
        OptionalDouble avgScore = domainDtos.stream()
                .filter(d -> d.score() != null)
                .mapToInt(PublicStatusDto.DomainStatusDto::score)
                .average();

        int overallScore = avgScore.isPresent() ? (int) avgScore.getAsDouble() : -1;
        String overallRisk = scoreToRisk(overallScore);

        return ResponseEntity.ok(new PublicStatusDto(
                account.getDisplayName(),
                account.getPlan() != null ? account.getPlan().name() : "FREE",
                LocalDateTime.now().format(FMT),
                overallScore,
                overallRisk,
                domainDtos
        ));
    }

    private PublicStatusDto.DomainStatusDto buildDomainStatus(Domain domain) {
        List<ScanRecord> records = scanRecordRepository
                .findByHostOrderByScannedAtDesc(domain.getHost(), PageRequest.of(0, 1));

        if (records.isEmpty()) {
            return new PublicStatusDto.DomainStatusDto(
                    domain.getHost(), domain.isVerified(),
                    null, null, null, false, PublicStatusDto.IssueCountsDto.EMPTY
            );
        }

        ScanRecord latest = records.get(0);
        ScanResult result = deserialize(latest);

        return new PublicStatusDto.DomainStatusDto(
                domain.getHost(),
                domain.isVerified(),
                latest.getScore(),
                latest.getRiskLevel() != null ? latest.getRiskLevel().name() : null,
                latest.getScannedAt().format(FMT),
                latest.isActiveMode(),
                countBySeverity(result)
        );
    }

    /**
     * Conta achados por severidade. Só o número sai daqui: título e correção
     * ficam de fora de propósito — ver o javadoc de {@link PublicStatusDto}.
     */
    private PublicStatusDto.IssueCountsDto countBySeverity(ScanResult result) {
        if (result == null || result.getScore() == null
                || result.getScore().getIssues() == null) {
            return PublicStatusDto.IssueCountsDto.EMPTY;
        }

        Map<String, Long> porSeveridade = result.getScore().getIssues().stream()
                .collect(Collectors.groupingBy(
                        i -> i.getSeverity() == null ? "" : i.getSeverity().toUpperCase(),
                        Collectors.counting()));

        return new PublicStatusDto.IssueCountsDto(
                porSeveridade.getOrDefault("CRITICAL", 0L),
                porSeveridade.getOrDefault("HIGH",     0L),
                porSeveridade.getOrDefault("MEDIUM",   0L),
                porSeveridade.getOrDefault("LOW",      0L));
    }

    private ScanResult deserialize(ScanRecord record) {
        try {
            return objectMapper.readValue(record.getResultJson(), ScanResult.class);
        } catch (Exception e) {
            return null;
        }
    }

    private String scoreToRisk(int score) {
        if (score < 0)  return "UNKNOWN";
        if (score < 20) return "CRITICAL";
        if (score < 45) return "HIGH";
        if (score < 70) return "MEDIUM";
        if (score < 85) return "LOW";
        return "SECURE";
    }
}
