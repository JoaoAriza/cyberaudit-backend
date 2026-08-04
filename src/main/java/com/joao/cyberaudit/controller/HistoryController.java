package com.joao.cyberaudit.controller;

import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.ScanOrigin;
import com.joao.cyberaudit.model.ScanResult;
import com.joao.cyberaudit.model.ScanSummary;
import com.joao.cyberaudit.service.ScanEntitlementService;
import com.joao.cyberaudit.service.ScanHistoryService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDate;
import java.util.List;
import java.util.UUID;

/**
 * Histórico de scans. TODO endpoint aqui é escopado pela conta do chamador —
 * host e scanId são informados pelo cliente e não provam nada sobre posse.
 */
@RestController
@RequestMapping("/history")
public class HistoryController {

    private final ScanHistoryService     historyService;
    private final ScanEntitlementService scanEntitlement;

    public HistoryController(ScanHistoryService historyService,
                             ScanEntitlementService scanEntitlement) {
        this.historyService  = historyService;
        this.scanEntitlement = scanEntitlement;
    }

    /**
     * Scans recentes da conta. origin=MANUAL|SCHEDULED (opcional, default: todos)
     */
    @GetMapping("/recent")
    public List<ScanSummary> recent(@AuthenticationPrincipal AppUser caller,
                                    @RequestParam(required = false) String origin) {
        Account account = requireAccount(caller);
        ScanOrigin o = parseOrigin(origin);
        var records = (o != null)
                ? historyService.findRecentByOrigin(account, 20, o)
                : historyService.findRecent(account, 20);
        return records.stream().map(ScanSummary::from).toList();
    }

    /**
     * Scans de um host, dentro da conta. origin=MANUAL|SCHEDULED (opcional, default: todos)
     * from/to: filtro de data ISO (YYYY-MM-DD) para gráfico intraday
     */
    @GetMapping("/{host}")
    public List<ScanSummary> byHost(@AuthenticationPrincipal AppUser caller,
                                     @PathVariable String host,
                                     @RequestParam(required = false) String origin,
                                     @RequestParam(required = false) String from,
                                     @RequestParam(required = false) String to) {
        Account account = requireAccount(caller);
        if (from != null && to != null) {
            LocalDate fromDate = LocalDate.parse(from);
            LocalDate toDate   = LocalDate.parse(to);
            return historyService.findByHostBetween(
                    account,
                    host,
                    fromDate.atStartOfDay(),
                    toDate.plusDays(1).atStartOfDay()
            ).stream().map(ScanSummary::from).toList();
        }
        ScanOrigin o = parseOrigin(origin);
        return historyService.findByHost(account, host, 50, o).stream()
                .map(ScanSummary::from)
                .toList();
    }

    /**
     * Resultado completo de um scan da própria conta, com o gating de plano aplicado —
     * sem ele, o histórico seria um caminho para ler detalhes que o plano trava no /scan.
     * Scan de outra conta responde 404 (não confirma existência).
     */
    @GetMapping("/{id}/result")
    public ResponseEntity<ScanResult> result(@AuthenticationPrincipal AppUser caller,
                                             @PathVariable UUID id) {
        Account account = requireAccount(caller);
        return historyService.getResult(id, account)
                .map(result -> ResponseEntity.ok(scanEntitlement.applyEntitlement(result, caller)))
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

    private Account requireAccount(AppUser caller) {
        if (caller == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "Autenticação necessária para consultar o histórico.");
        }
        Account account = caller.getAccount();
        if (account == null) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "Usuário sem conta associada não possui histórico.");
        }
        return account;
    }

    private ScanOrigin parseOrigin(String origin) {
        if (origin == null || origin.isBlank()) return null;
        try { return ScanOrigin.valueOf(origin.toUpperCase()); }
        catch (IllegalArgumentException e) { return null; }
    }
}
