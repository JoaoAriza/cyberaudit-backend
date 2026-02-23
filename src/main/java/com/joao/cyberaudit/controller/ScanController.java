package com.joao.cyberaudit.controller;

import com.joao.cyberaudit.model.*;
import com.joao.cyberaudit.service.*;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/scan")
public class ScanController {

    private final SSLService sslService;
    private final HeaderService headerService;
    private final ScoreService scoreService;
    private final HttpFetchService httpFetchService;
    private final ReportService reportService;
    private final ErrorDisclosureService errorDisclosureService;
    private final PortScanService portScanService;
    private final XssProbeService xssProbeService;
    private final PdfReportService pdfReportService;

    public ScanController(
            SSLService sslService,
            HeaderService headerService,
            ScoreService scoreService,
            HttpFetchService httpFetchService,
            ReportService reportService,
            ErrorDisclosureService errorDisclosureService,
            PortScanService portScanService,
            XssProbeService xssProbeService,
            PdfReportService pdfReportService
    ) {
        this.sslService = sslService;
        this.headerService = headerService;
        this.scoreService = scoreService;
        this.httpFetchService = httpFetchService;
        this.reportService = reportService;
        this.errorDisclosureService = errorDisclosureService;
        this.portScanService = portScanService;
        this.xssProbeService = xssProbeService;
        this.pdfReportService = pdfReportService;
    }

    @GetMapping
    public ScanResult scan(@RequestParam String url,
                           @RequestParam(defaultValue = "false") boolean active) {

        String inputUrl = normalizeUrl(url);

        // 1) Verifica redirect HTTP -> HTTPS
        String httpProbeUrl = inputUrl.startsWith("https://")
                ? "http://" + inputUrl.substring("https://".length())
                : inputUrl;

        boolean redirectsToHttps = httpFetchService.traceRedirectToHttps(httpProbeUrl);

        // 2) SSL check em HTTPS (se possível)
        String httpsUrl = toHttps(inputUrl);
        SSLInfo sslInfo = sslService.checkSSL(httpsUrl);
        boolean supportsHttps = sslInfo.isHttps() && sslInfo.isValid();

        // 3) Decide URL para analisar headers
        String analysisUrl = supportsHttps ? httpsUrl : inputUrl;

        HttpFetchResult fetch = httpFetchService.fetchHeaders(analysisUrl);

        Map<String, String> analyzedHeaders;
        if (fetch.getError() != null) {
            analyzedHeaders = Map.of("error", fetch.getError());
        } else {
            analyzedHeaders = headerService.analyzeSecurityHeaders(fetch.getHeaders());
        }

        // target final (usa finalUrl quando existir)
        String target = (fetch.getFinalUrl() != null) ? fetch.getFinalUrl() : analysisUrl;

        // PASSIVO: só detecta superfície de entrada
        boolean inputSurfaceDetected = errorDisclosureService.hasQueryParams(target);

        // XSS (ACTIVE + somente se tiver superfície)
        boolean xssProbePerformed = false;
        boolean reflectedXssSuspected = false;

        if (active && inputSurfaceDetected) {
            xssProbePerformed = true;
            reflectedXssSuspected = xssProbeService.reflectedMarkerAppears(target);
        }

        // DB error leakage (ACTIVE)
        boolean dbErrorLeakageSuspected = false;
        if (active) {
            dbErrorLeakageSuspected = errorDisclosureService.detectsDbErrorLeakage(target);
        }

        // Port scan (ACTIVE)
        java.util.List<PortFinding> openPorts = java.util.List.of();
        if (active) {
            String host = extractHost(target);
            if (host != null && !host.isBlank()) {
                openPorts = portScanService.scanCommonPorts(host);
            }
        }

        // Score
        ScoreResult score = scoreService.calculate(
                sslInfo,
                analyzedHeaders,
                redirectsToHttps,
                active,
                inputSurfaceDetected,
                dbErrorLeakageSuspected,
                xssProbePerformed,
                reflectedXssSuspected,
                openPorts
        );

        return new ScanResult(
                inputUrl,
                fetch.getFinalUrl(),
                fetch.getStatusCode(),
                redirectsToHttps,
                active,
                inputSurfaceDetected,
                dbErrorLeakageSuspected,
                xssProbePerformed,
                reflectedXssSuspected,
                sslInfo,
                analyzedHeaders,
                score,
                openPorts
        );
    }

    @GetMapping(value = "/report", produces = "text/plain; charset=UTF-8")
    public String scanReport(@RequestParam String url,
                             @RequestParam(defaultValue = "false") boolean active) {
        ScanResult result = scan(url, active);
        return reportService.generateReport(result);
    }

    @GetMapping(value = "/report/pdf", produces = "application/pdf")
    public byte[] scanReportPdf(@RequestParam String url,
                                @RequestParam(defaultValue = "false") boolean active) {
        ScanResult result = scan(url, false);
        String reportText = reportService.generateReport(result);
        return pdfReportService.generatePdf(result, reportText);
    }

    private String normalizeUrl(String url) {
        String u = url.trim();
        if (!u.startsWith("http://") && !u.startsWith("https://")) {
            u = "https://" + u;
        }
        return u;
    }

    private String toHttps(String url) {
        if (url.startsWith("https://")) return url;
        if (url.startsWith("http://")) return "https://" + url.substring("http://".length());
        return "https://" + url;
    }

    private String extractHost(String url) {
        try {
            return java.net.URI.create(url).getHost();
        } catch (Exception e) {
            return null;
        }
    }
}