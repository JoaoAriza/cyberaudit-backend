package com.joao.cyberaudit.controller;

import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.ScanOrigin;
import com.joao.cyberaudit.model.ScanResult;
import com.joao.cyberaudit.model.ScanSummary;
import com.joao.cyberaudit.service.ScanHistoryService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/history")
public class HistoryController {

    private final ScanHistoryService historyService;

    public HistoryController(ScanHistoryService historyService) {
        this.historyService = historyService;
    }

    /**
     * Scans recentes. origin=MANUAL|SCHEDULED (opcional, default: todos)
     */
    @GetMapping("/recent")
    public List<ScanSummary> recent(@RequestParam(required = false) String origin) {
        ScanOrigin o = parseOrigin(origin);
        var records = (o != null)
                ? historyService.findRecentByOrigin(20, o)
                : historyService.findRecent(20);
        return records.stream().map(ScanSummary::from).toList();
    }

    /**
     * Scans de um host. origin=MANUAL|SCHEDULED (opcional, default: todos)
     * from/to: filtro de data ISO (YYYY-MM-DD) para gráfico intraday
     */
    @GetMapping("/{host}")
    public List<ScanSummary> byHost(@PathVariable String host,
                                     @RequestParam(required = false) String origin,
                                     @RequestParam(required = false) String from,
                                     @RequestParam(required = false) String to) {
        if (from != null && to != null) {
            LocalDate fromDate = LocalDate.parse(from);
            LocalDate toDate   = LocalDate.parse(to);
            return historyService.findByHostBetween(
                    host,
                    fromDate.atStartOfDay(),
                    toDate.plusDays(1).atStartOfDay()
            ).stream().map(ScanSummary::from).toList();
        }
        ScanOrigin o = parseOrigin(origin);
        return historyService.findByHost(host, 50, o).stream()
                .map(ScanSummary::from)
                .toList();
    }

    @GetMapping("/{id}/result")
    public ResponseEntity<ScanResult> result(@PathVariable UUID id) {
        return historyService.getResult(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Último scan por domínio para a conta do usuário autenticado.
     * Usado na aba "Visão Geral" do Histórico.
     */
    @GetMapping("/overview")
    public List<ScanSummary> overview(@AuthenticationPrincipal AppUser caller) {
        if (caller == null || caller.getAccount() == null) return List.of();
        return historyService.findLatestPerHost(caller.getAccount(), 50)
                .stream().map(ScanSummary::from).toList();
    }

    private ScanOrigin parseOrigin(String origin) {
        if (origin == null || origin.isBlank()) return null;
        try { return ScanOrigin.valueOf(origin.toUpperCase()); }
        catch (IllegalArgumentException e) { return null; }
    }
}
