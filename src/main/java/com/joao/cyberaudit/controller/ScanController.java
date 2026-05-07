package com.joao.cyberaudit.controller;

import com.joao.cyberaudit.model.*;
import com.joao.cyberaudit.service.*;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.net.URI;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/scan")
public class ScanController {

    private final SSLService             sslService;
    private final TlsVersionService      tlsVersionService;
    private final HeaderService          headerService;
    private final ScoreService           scoreService;
    private final HttpFetchService       httpFetchService;
    private final ReportService          reportService;
    private final ErrorDisclosureService errorDisclosureService;
    private final PortScanService        portScanService;
    private final XssProbeService        xssProbeService;
    private final PdfReportService       pdfReportService;
    private final ScanCacheService       scanCacheService;
    private final RateLimitService       rateLimitService;
    private final CorsAnalyzerService    corsAnalyzerService;
    private final CookieSecurityService  cookieSecurityService;
    private final RobotsTxtService       robotsTxtService;

    public ScanController(
            SSLService sslService,
            TlsVersionService tlsVersionService,
            HeaderService headerService,
            ScoreService scoreService,
            HttpFetchService httpFetchService,
            ReportService reportService,
            ErrorDisclosureService errorDisclosureService,
            PortScanService portScanService,
            XssProbeService xssProbeService,
            PdfReportService pdfReportService,
            ScanCacheService scanCacheService,
            RateLimitService rateLimitService,
            CorsAnalyzerService corsAnalyzerService,
            CookieSecurityService cookieSecurityService,
            RobotsTxtService robotsTxtService
    ) {
        this.sslService             = sslService;
        this.tlsVersionService      = tlsVersionService;
        this.headerService          = headerService;
        this.scoreService           = scoreService;
        this.httpFetchService       = httpFetchService;
        this.reportService          = reportService;
        this.errorDisclosureService = errorDisclosureService;
        this.portScanService        = portScanService;
        this.xssProbeService        = xssProbeService;
        this.pdfReportService       = pdfReportService;
        this.scanCacheService       = scanCacheService;
        this.rateLimitService       = rateLimitService;
        this.corsAnalyzerService    = corsAnalyzerService;
        this.cookieSecurityService  = cookieSecurityService;
        this.robotsTxtService       = robotsTxtService;
    }

    // ── Endpoints ─────────────────────────────────────────

    @GetMapping
    public ScanResult scan(@RequestParam String url,
                           @RequestParam(defaultValue = "false") boolean active,
                           HttpServletRequest request) {
        return doScan(url, active, request);
    }

    @GetMapping(value = "/report", produces = "text/plain; charset=UTF-8")
    public String scanReport(@RequestParam String url,
                             @RequestParam(defaultValue = "false") boolean active,
                             HttpServletRequest request) {
        return reportService.generateReport(doScan(url, active, request));
    }

    @GetMapping(value = "/report/pdf", produces = "application/pdf")
    public byte[] scanReportPdf(@RequestParam String url,
                                @RequestParam(defaultValue = "false") boolean active,
                                HttpServletRequest request) {
        ScanResult result = doScan(url, active, request);
        return pdfReportService.generatePdf(result, reportService.generateReport(result));
    }

    // ── Core ──────────────────────────────────────────────

    private ScanResult doScan(String url, boolean active, HttpServletRequest request) {

        // Rate limit: 10 req / 60s por IP
        if (!rateLimitService.allow(request.getRemoteAddr(), 10, 60_000)) {
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,
                    "Muitas requisições. Tente novamente em alguns segundos.");
        }

        String inputUrl = normalizeUrl(url);
        String cacheKey = buildCacheKey(inputUrl, active);

        ScanResult cached = scanCacheService.get(cacheKey, ScanResult.class);
        if (cached != null) return cached;

        // ── 1. SSL ──────────────────────────────────────────
        String  httpsUrl      = toHttps(inputUrl);
        SSLInfo sslInfo       = sslService.checkSSL(httpsUrl);
        boolean supportsHttps = sslInfo.isHttps() && sslInfo.isValid();

        // ── 2. TLS version ──────────────────────────────────
        String     host       = extractHostSafe(httpsUrl);
        TlsDetails tlsDetails = (supportsHttps && host != null)
                ? tlsVersionService.inspect(host, 443)
                : new TlsDetails("N/A", "N/A", false, "HTTPS não disponível");

        // ── 3. HTTP → HTTPS redirect ────────────────────────
        boolean redirectsToHttps = httpFetchService.traceRedirectToHttps(toHttp(inputUrl));

        // ── 4. Headers + cookies ────────────────────────────
        String          analysisUrl = supportsHttps ? httpsUrl : inputUrl;
        HttpFetchResult fetch       = httpFetchService.fetchHeaders(analysisUrl);

        Map<String, String> analyzedHeaders;
        boolean serverVersionExposed = false;

        if (fetch.getError() != null) {
            analyzedHeaders = Map.of("error", fetch.getError());
        } else {
            analyzedHeaders      = headerService.analyzeSecurityHeaders(fetch.getHeaders());
            serverVersionExposed = headerService.detectsServerVersionExposure(fetch.getHeaders());
        }

        String target = fetch.getFinalUrl() != null ? fetch.getFinalUrl() : analysisUrl;

        // ── 5. CORS ─────────────────────────────────────────
        CorsResult corsResult = corsAnalyzerService.analyze(target);

        // ── 6. Cookies ──────────────────────────────────────
        List<CookieFinding> cookieIssues = cookieSecurityService.analyze(fetch.getRawSetCookies());

        // ── 7. robots.txt ───────────────────────────────────
        List<String> sensitiveRobotsPaths = robotsTxtService.findSensitivePaths(target);

        // ── 8. Superficie de entrada (passivo) ───────────────
        boolean inputSurfaceDetected = errorDisclosureService.hasQueryParams(target);

        // ── 9. Checks ativos ─────────────────────────────────
        boolean xssProbePerformed     = false;
        boolean reflectedXssSuspected = false;
        boolean dbErrorLeakage        = false;
        List<PortFinding> openPorts   = List.of();

        if (active) {
            if (inputSurfaceDetected) {
                xssProbePerformed     = true;
                reflectedXssSuspected = xssProbeService.reflectedMarkerAppears(target);
                dbErrorLeakage        = errorDisclosureService.detectsDbErrorLeakage(target);
            }
            if (host != null && !host.isBlank()) {
                openPorts = portScanService.scanCommonPorts(host);
            }
        }

        // ── 10. Score ────────────────────────────────────────
        ScoreResult score = scoreService.calculate(
                sslInfo, tlsDetails, analyzedHeaders, redirectsToHttps,
                active, inputSurfaceDetected, dbErrorLeakage,
                xssProbePerformed, reflectedXssSuspected, openPorts,
                corsResult, cookieIssues, sensitiveRobotsPaths, serverVersionExposed
        );

        ScanResult result = ScanResult.builder()
                .url(inputUrl)
                .finalUrl(fetch.getFinalUrl())
                .httpStatus(fetch.getStatusCode())
                .redirectsToHttps(redirectsToHttps)
                .sslInfo(sslInfo)
                .tlsDetails(tlsDetails)
                .headers(analyzedHeaders)
                .serverVersionExposed(serverVersionExposed)
                .activeMode(active)
                .inputSurfaceDetected(inputSurfaceDetected)
                .dbErrorLeakageSuspected(dbErrorLeakage)
                .xssProbePerformed(xssProbePerformed)
                .reflectedXssSuspected(reflectedXssSuspected)
                .openPorts(openPorts)
                .corsResult(corsResult)
                .cookieIssues(cookieIssues)
                .sensitiveRobotsPaths(sensitiveRobotsPaths)
                .score(score)
                .build();

        scanCacheService.put(cacheKey, result);
        return result;
    }

    // ── Utilitários ───────────────────────────────────────

    private String normalizeUrl(String url) {
        String u = url.trim();
        if (!u.startsWith("http://") && !u.startsWith("https://")) u = "https://" + u;
        return u;
    }

    private String toHttps(String url) {
        if (url.startsWith("https://")) return url;
        if (url.startsWith("http://"))  return "https://" + url.substring(7);
        return "https://" + url;
    }

    private String toHttp(String url) {
        if (url.startsWith("http://"))  return url;
        if (url.startsWith("https://")) return "http://" + url.substring(8);
        return "http://" + url;
    }

    private String extractHostSafe(String url) {
        try { return URI.create(url).getHost(); }
        catch (Exception e) { return null; }
    }

    private String buildCacheKey(String url, boolean active) {
        String h = extractHostSafe(url);
        return "scan:" + (h != null ? h : url) + ":active=" + active;
    }
}