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

    public ScanController(
            ScanOrchestrator scanOrchestrator,
            AsyncScanService asyncScanService,
            ReportService reportService,
            PdfReportService pdfReportService,
            RateLimitService rateLimitService,
            DomainProtectionService domainProtectionService,
            GuestRateLimitService guestRateLimitService,
            PlanLimitService planLimitService,
            ScanEntitlementService scanEntitlement) {
        this.scanOrchestrator        = scanOrchestrator;
        this.asyncScanService        = asyncScanService;
        this.reportService           = reportService;
        this.pdfReportService        = pdfReportService;
        this.rateLimitService        = rateLimitService;
        this.domainProtectionService = domainProtectionService;
        this.guestRateLimitService   = guestRateLimitService;
        this.planLimitService        = planLimitService;
        this.scanEntitlement         = scanEntitlement;
    }

    // ── Scan síncrono ─────────────────────────────────────────────────────────

    @GetMapping
    public ScanResult scan(@RequestParam String url,
                           @RequestParam(defaultValue = "false") boolean active,
                           HttpServletRequest request) {
        AppUser currentUser = getCurrentUser();
        checkRateLimit(request, currentUser);
        if (active && currentUser == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "Scan ativo requer autenticação. Faça login ou solicite um convite.");
        }
        if (currentUser == null) {
            guestRateLimitService.checkAndIncrement(request.getRemoteAddr());
        } else {
            if (active) planLimitService.checkActiveScan(currentUser, url);
            planLimitService.checkAndIncrementDailyScan(currentUser);
        }
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
        return reportService.generateReport(scanEntitlement.applyEntitlement(
                scanOrchestrator.execute(url, active, currentUser, false), currentUser));
    }

    // ── Relatório PDF — via scanId (sem re-scan, resultado já em memória) ───────

    @GetMapping(value = "/report/pdf/{scanId}", produces = "application/pdf")
    public ResponseEntity<byte[]> scanReportPdfByScanId(@PathVariable String scanId) {
        AppUser currentUser = getCurrentUser();
        if (currentUser == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "Geração de PDF requer autenticação. Faça login para continuar.");
        }

        planLimitService.checkPdfExport(currentUser);

        AsyncScanStatus status = asyncScanService.getStatus(scanId);
        if (status == null || status.getResult() == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND,
                    "Resultado de scan não encontrado. Realize um novo scan antes de exportar o PDF.");
        }

        ScanResult result = status.getResult();
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
        planLimitService.checkPdfExport(currentUser);
        checkRateLimit(request, currentUser);
        ScanResult result = scanOrchestrator.execute(url, active, currentUser, false);
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

        if (active && currentUser == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "Scan ativo requer autenticação.");
        }
        if (currentUser == null) {
            guestRateLimitService.checkAndIncrement(request.getRemoteAddr());
        } else {
            if (active) planLimitService.checkActiveScan(currentUser, url);
            planLimitService.checkAndIncrementDailyScan(currentUser);
        }

        String scanId = asyncScanService.submit(url, active, currentUser, refresh, notify);
        return ResponseEntity.accepted().body(Map.of("scanId", scanId));
    }

    @GetMapping("/async/{scanId}")
    public ResponseEntity<AsyncScanStatus> getAsyncStatus(@PathVariable String scanId) {
        AsyncScanStatus status = asyncScanService.getStatus(scanId);
        if (status == null) return ResponseEntity.notFound().build();
        return ResponseEntity.ok(status);
    }

    // ── Verificação de propriedade ────────────────────────────────────────────

    @GetMapping("/verify-token")
    public ResponseEntity<Map<String, String>> verifyToken(@RequestParam String host) {
        String token = domainProtectionService.generateVerificationToken(host);
        return ResponseEntity.ok(Map.of(
                "host",         host,
                "token",        token,
                "instructions", "Crie o arquivo /.well-known/cyberaudit.txt com o conteúdo acima",
                "verifyUrl",    "https://" + host + "/.well-known/cyberaudit.txt"
        ));
    }

    @GetMapping("/verify-check")
    public ResponseEntity<Map<String, Object>> verifyCheck(@RequestParam String host) {
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

    private void checkRateLimit(HttpServletRequest request, AppUser currentUser) {
        if (!rateLimitService.allow(request.getRemoteAddr(), currentUser)) {
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