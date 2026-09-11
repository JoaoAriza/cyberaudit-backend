package com.joao.cyberaudit.controller;

import com.joao.cyberaudit.dto.PathSummaryDto;
import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.ScanOrigin;
import com.joao.cyberaudit.model.ScanResult;
import com.joao.cyberaudit.model.ScanSummary;
import com.joao.cyberaudit.service.ScanEntitlementService;
import com.joao.cyberaudit.service.ScanHistoryService;
import com.joao.cyberaudit.service.UserTimeZoneService;
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
    private final UserTimeZoneService    userTimeZone;

    public HistoryController(ScanHistoryService historyService,
                             ScanEntitlementService scanEntitlement,
                             UserTimeZoneService userTimeZone) {
        this.historyService  = historyService;
        this.scanEntitlement = scanEntitlement;
        this.userTimeZone    = userTimeZone;
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
        return records;
    }

    /**
     * Um card por CAMINHO scaneado, com o score do scan mais recente dele.
     *
     * Complementa o /overview, que responde por domínio: aqui o /login e a home
     * do mesmo domínio aparecem separados, cada um com a sua nota.
     */
    @GetMapping("/paths")
    public List<PathSummaryDto> paths(@AuthenticationPrincipal AppUser caller) {
        return historyService.findLatestPerPath(requireAccount(caller), 500);
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
                                     @RequestParam(required = false) String to,
                                     @RequestParam(required = false) String path) {
        Account account = requireAccount(caller);
        boolean porCaminho = path != null && !path.isBlank();

        List<ScanSummary> scans;
        if (from != null && to != null) {
            LocalDate fromDate = LocalDate.parse(from);
            LocalDate toDate   = LocalDate.parse(to);
            scans = historyService.findByHostBetween(
                    account,
                    host,
                    UserTimeZoneService.inicioDoDia(fromDate, userTimeZone.zonaDe(caller)),
                    UserTimeZoneService.inicioDoDia(toDate.plusDays(1), userTimeZone.zonaDe(caller))
            );
        } else {
            // Com caminho, a janela é maior ANTES de filtrar: os 50 scans mais
            // recentes do domínio podem ser todos da home, e o /login sumiria do
            // gráfico mesmo tendo histórico. É projeção, sem o laudo — 300 linhas
            // custam pouco.
            scans = historyService.findByHost(account, host, porCaminho ? 300 : 50, parseOrigin(origin));
        }

        // Com path, só a página pedida — vale também para o intraday, que antes
        // devolvia o dia inteiro do domínio e misturava as páginas no gráfico.
        // Sem path, o domínio inteiro, como antes.
        if (!porCaminho) return scans;
        String alvo = ScanHistoryService.normalizarCaminho(path);
        return scans.stream()
                .filter(s -> ScanHistoryService.caminhoDe(s.getUrl()).equals(alvo))
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
        return historyService.findLatestPerHost(caller.getAccount(), 50);
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
