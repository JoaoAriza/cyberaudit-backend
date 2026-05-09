package com.joao.cyberaudit.controller;

import com.joao.cyberaudit.model.AsyncScanStatus;
import com.joao.cyberaudit.model.ScanResult;
import com.joao.cyberaudit.service.*;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;

@RestController
@RequestMapping("/scan")
public class ScanController {

    private final ScanOrchestrator  scanOrchestrator;
    private final AsyncScanService  asyncScanService;
    private final ReportService     reportService;
    private final PdfReportService  pdfReportService;
    private final RateLimitService  rateLimitService;
    private final DomainProtectionService domainProtectionService;

    public ScanController(
            ScanOrchestrator scanOrchestrator,
            AsyncScanService asyncScanService,
            ReportService reportService,
            PdfReportService pdfReportService,
            RateLimitService rateLimitService,
            DomainProtectionService domainProtectionService
    ) {
        this.scanOrchestrator = scanOrchestrator;
        this.asyncScanService = asyncScanService;
        this.reportService    = reportService;
        this.pdfReportService = pdfReportService;
        this.rateLimitService = rateLimitService;
        this.domainProtectionService = domainProtectionService;
    }

    @GetMapping
    public ScanResult scan(@RequestParam String url,
                           @RequestParam(defaultValue = "false") boolean active,
                           HttpServletRequest request) {
        checkRateLimit(request);
        return scanOrchestrator.execute(url, active);
    }

    @GetMapping(value = "/report", produces = "text/plain; charset=UTF-8")
    public String scanReport(@RequestParam String url,
                             @RequestParam(defaultValue = "false") boolean active,
                             HttpServletRequest request) {
        checkRateLimit(request);
        return reportService.generateReport(scanOrchestrator.execute(url, active));
    }

    @GetMapping(value = "/report/pdf", produces = "application/pdf")
    public byte[] scanReportPdf(@RequestParam String url,
                                @RequestParam(defaultValue = "false") boolean active,
                                HttpServletRequest request) {
        checkRateLimit(request);
        ScanResult result = scanOrchestrator.execute(url, active);
        return pdfReportService.generatePdf(result, reportService.generateReport(result));
    }

    @PostMapping("/async")
    public ResponseEntity<Map<String, String>> submitAsync(
            @RequestParam String url,
            @RequestParam(defaultValue = "false") boolean active,
            HttpServletRequest request) {

        checkRateLimit(request);
        String scanId = asyncScanService.submit(url, active);
        return ResponseEntity
                .accepted()  // 202 Accepted
                .body(Map.of("scanId", scanId));
    }

    @GetMapping("/async/{scanId}")
    public ResponseEntity<AsyncScanStatus> getAsyncStatus(@PathVariable String scanId) {
        AsyncScanStatus status = asyncScanService.getStatus(scanId);
        if (status == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(status);
    }

    private void checkRateLimit(HttpServletRequest request) {
        if (!rateLimitService.allow(request.getRemoteAddr(), 10, 60_000)) {
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,
                    "Muitas requisições. Tente novamente em alguns segundos.");
        }
    }

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
}