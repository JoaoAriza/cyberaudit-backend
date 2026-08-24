package com.joao.cyberaudit.controller;

import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.AsyncScanStatus;
import com.joao.cyberaudit.model.ScanResult;
import com.joao.cyberaudit.service.*;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;

@RestController
@RequestMapping("/scan")
public class ScanController {

    private final ScanOrchestrator        scanOrchestrator;
    private final AsyncScanService        asyncScanService;
    private final ReportService           reportService;
    private final PdfReportService        pdfReportService;
    private final RateLimitService        rateLimitService;
    private final DomainProtectionService domainProtectionService;
    private final GuestRateLimitService   guestRateLimitService;
    private final PlanLimitService        planLimitService;
    private final ScanEntitlementService  scanEntitlement;
    private final ClientIpResolver        clientIpResolver;

    public ScanController(
            ScanOrchestrator scanOrchestrator,
            AsyncScanService asyncScanService,
            ReportService reportService,
            PdfReportService pdfReportService,
            RateLimitService rateLimitService,
            DomainProtectionService domainProtectionService,
            GuestRateLimitService guestRateLimitService,
            PlanLimitService planLimitService,
            ScanEntitlementService scanEntitlement,
            ClientIpResolver clientIpResolver) {
        this.scanOrchestrator        = scanOrchestrator;
        this.asyncScanService        = asyncScanService;
        this.reportService           = reportService;
        this.pdfReportService        = pdfReportService;
        this.rateLimitService        = rateLimitService;
        this.domainProtectionService = domainProtectionService;
        this.guestRateLimitService   = guestRateLimitService;
        this.planLimitService        = planLimitService;
        this.scanEntitlement         = scanEntitlement;
        this.clientIpResolver        = clientIpResolver;
    }

    // ── Scan síncrono ─────────────────────────────────────────────────────────

    @GetMapping
    public ScanResult scan(@RequestParam String url,
                           @RequestParam(defaultValue = "false") boolean active,
                           HttpServletRequest request) {
        AppUser currentUser = getCurrentUser();
        checkRateLimit(request, currentUser);
        enforceScanLimits(url, active, currentUser, request);
        return scanEntitlement.applyEntitlement(
                scanOrchestrator.execute(url, active, currentUser, false), currentUser);
    }

    // ── Relatório texto ───────────────────────────────────────────────────────

    @GetMapping(value = "/report", produces = "text/plain; charset=UTF-8")
    public String scanReport(@RequestParam String url,
                             @RequestParam(defaultValue = "false") boolean active,
                             HttpServletRequest request) {
        AppUser currentUser = getCurrentUser();
        checkRateLimit(request, currentUser);
        // Mesmas travas do GET /scan: este endpoint dispara um scan completo e é
        // público — sem isso era o caminho para scan ativo anônimo e ilimitado.
        enforceScanLimits(url, active, currentUser, request);
        return reportService.generateReport(scanEntitlement.applyEntitlement(
                scanOrchestrator.execute(url, active, currentUser, false), currentUser));
    }

    // ── Relatório PDF — via scanId (sem re-scan, resultado já em memória) ───────

    @GetMapping(value = "/report/pdf/{scanId}", produces = "application/pdf")
    public ResponseEntity<byte[]> scanReportPdfByScanId(@PathVariable String scanId,
                                                         HttpServletRequest request) {
        AppUser currentUser = getCurrentUser();
        if (currentUser == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "Geração de PDF requer autenticação. Faça login para continuar.");
        }

        // Só o autor do scan exporta o PDF dele — o scanId é um UUID, não uma credencial.
        AsyncScanStatus status = asyncScanService.getStatusFor(scanId,
                AsyncScanService.ownerKey(currentUser, clientIpResolver.resolve(request)));
        if (status == null || status.getResult() == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND,
                    "Resultado de scan não encontrado. Realize um novo scan antes de exportar o PDF.");
        }

        ScanResult result = status.getResult();
        // A trava de plano depende do host, então só dá para conferir depois de
        // saber qual scan é. O status guardado já vem com o gating de detalhe.
        planLimitService.checkPdfExport(currentUser, result.getUrl());
        byte[] pdf = pdfReportService.generatePdf(
                result, reportService.generateReport(result), currentUser.getAccount());

        String filename = "cyberaudit-" + (result.getUrl() != null
                ? result.getUrl().replaceAll("[^a-zA-Z0-9]", "-") : "report") + ".pdf";

        return ResponseEntity.ok()
                .header("Content-Disposition", "attachment; filename=\"" + filename + "\"")
                .header("Content-Type", "application/pdf")
                .body(pdf);
    }

    // ── Relatório PDF — re-scan completo (fallback) ────────────────────────────

    @GetMapping(value = "/report/pdf", produces = "application/pdf")
    public byte[] scanReportPdf(@RequestParam String url,
                                @RequestParam(defaultValue = "false") boolean active,
                                HttpServletRequest request) {
        AppUser currentUser = getCurrentUser();
        if (currentUser == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "Geração de PDF requer autenticação. Faça login para continuar.");
        }
        planLimitService.checkPdfExport(currentUser, url);
        checkRateLimit(request, currentUser);
        // Re-scan completo: consome limite diário como qualquer outro scan.
        enforceScanLimits(url, active, currentUser, request);
        // Caminho de re-scan: o resultado sai cru do orchestrator, ao contrário do
        // PDF por scanId, que lê o status já travado pelo AsyncScanService. Sem isto
        // o PDF virava a porta dos fundos para o detalhe que a tela esconde.
        ScanResult result = scanEntitlement.applyEntitlement(
                scanOrchestrator.execute(url, active, currentUser, false), currentUser);
        return pdfReportService.generatePdf(
                result, reportService.generateReport(result), currentUser.getAccount());
    }

    // ── Scan assíncrono ───────────────────────────────────────────────────────

    @PostMapping("/async")
    public ResponseEntity<Map<String, String>> submitAsync(
            @RequestParam String url,
            @RequestParam(defaultValue = "false") boolean active,
            @RequestParam(defaultValue = "false") boolean refresh,
            @RequestParam(defaultValue = "false") boolean notify,
            HttpServletRequest request) {

        AppUser currentUser = getCurrentUser();
        checkRateLimit(request, currentUser);
        enforceScanLimits(url, active, currentUser, request);
        // Recusa aqui, na submissão: o scan roda em thread assíncrona e uma falha
        // lá vira scan perdido em vez de mensagem na tela.
        if (notify) planLimitService.checkEmailNotify(currentUser, url);

        String scanId = asyncScanService.submit(url, active, currentUser, refresh, notify,
                AsyncScanService.ownerKey(currentUser, clientIpResolver.resolve(request)));
        return ResponseEntity.accepted().body(Map.of("scanId", scanId));
    }

    /**
     * Endpoint público: o scanId sozinho não autoriza nada, então o resultado só
     * volta para quem submeteu (usuário autenticado ou mesmo IP, para guest).
     */
    @GetMapping("/async/{scanId}")
    public ResponseEntity<AsyncScanStatus> getAsyncStatus(@PathVariable String scanId,
                                                          HttpServletRequest request) {
        AsyncScanStatus status = asyncScanService.getStatusFor(scanId,
                AsyncScanService.ownerKey(getCurrentUser(), clientIpResolver.resolve(request)));
        if (status == null) return ResponseEntity.notFound().build();
        return ResponseEntity.ok(status);
    }

    // ── Verificação de propriedade ────────────────────────────────────────────

    @GetMapping("/verify-token")
    public ResponseEntity<Map<String, String>> verifyToken(@RequestParam String host) {
        SsrfGuard.validateHost(host);
        String token = domainProtectionService.generateVerificationToken(host);
        return ResponseEntity.ok(Map.of(
                "host",         host,
                "token",        token,
                "instructions", "Crie o arquivo /.well-known/cyberaudit.txt com o conteúdo acima",
                "verifyUrl",    "https://" + host + "/.well-known/cyberaudit.txt"
        ));
    }

    /**
     * Público (guests usam no OwnershipCard) e faz requisição de saída para o host
     * informado: passa pelo SsrfGuard antes e consome rate-limit como qualquer
     * endpoint que gera tráfego externo.
     */
    @GetMapping("/verify-check")
    public ResponseEntity<Map<String, Object>> verifyCheck(@RequestParam String host,
                                                           HttpServletRequest request) {
        checkRateLimit(request, getCurrentUser());
        SsrfGuard.validateHost(host);
        boolean verified = domainProtectionService.isOwnershipVerified(host);
        return ResponseEntity.ok(Map.of(
                "host",     host,
                "verified", verified,
                "message",  verified
                        ? "Verificação OK. Scan ativo liberado."
                        : "Arquivo não encontrado ou token inválido."
        ));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Travas de custo de TODO endpoint que dispara um scan: scan ativo exige login,
     * guest consome a cota diária por IP e usuário consome a cota do plano.
     *
     * Estava duplicado em /scan e /scan/async e ausente em /scan/report e
     * /scan/report/pdf — o que fazia dos dois últimos um bypass completo dos limites.
     */
    private void enforceScanLimits(String url, boolean active,
                                   AppUser currentUser, HttpServletRequest request) {
        if (active && currentUser == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "Scan ativo requer autenticação. Faça login ou solicite um convite.");
        }
        if (currentUser == null) {
            guestRateLimitService.checkAndIncrement(clientIpResolver.resolve(request));
        } else {
            if (active) planLimitService.checkActiveScan(currentUser, url);
            planLimitService.checkAndIncrementDailyScan(currentUser);
        }
    }

    private void checkRateLimit(HttpServletRequest request, AppUser currentUser) {
        if (!rateLimitService.allow(clientIpResolver.resolve(request), currentUser)) {
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,
                    "Muitas requisições. " +
                            (currentUser == null
                                    ? "Limite de " + RateLimitService.GUEST_RPM
                                    + " requests/min para visitantes."
                                    : "Tente novamente em alguns segundos.")
            );
        }
    }

    private AppUser getCurrentUser() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()
                || auth.getPrincipal() instanceof String) {
            return null;
        }
        return (AppUser) auth.getPrincipal();
    }
}