package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.*;
import com.joao.cyberaudit.exception.OwnershipNotVerifiedException;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;

@Service
public class ScanOrchestrator {

    private final SSLService              sslService;
    private final TlsVersionService       tlsVersionService;
    private final HeaderService           headerService;
    private final ScoreService            scoreService;
    private final HttpFetchService        httpFetchService;
    private final ErrorDisclosureService  errorDisclosureService;
    private final PortScanService         portScanService;
    private final XssProbeService         xssProbeService;
    private final WafDetectionService     wafDetectionService;
    private final ScanCacheService        scanCacheService;
    private final CorsAnalyzerService     corsAnalyzerService;
    private final CookieSecurityService   cookieSecurityService;
    private final RobotsTxtService        robotsTxtService;
    private final DnsSecurityService      dnsSecurityService;
    private final ScanHistoryService      scanHistoryService;
    private final DomainProtectionService domainProtectionService;
    private final SensitiveFileService    sensitiveFileService;
    private final HttpMethodService       httpMethodService;
    private final SecurityTxtService      securityTxtService;
    private final OpenRedirectService     openRedirectService;
    private final DirectoryListingService directoryListingService;

    public ScanOrchestrator(
            SSLService sslService, TlsVersionService tlsVersionService,
            HeaderService headerService, ScoreService scoreService,
            HttpFetchService httpFetchService, ErrorDisclosureService errorDisclosureService,
            PortScanService portScanService, XssProbeService xssProbeService,
            WafDetectionService wafDetectionService, ScanCacheService scanCacheService,
            CorsAnalyzerService corsAnalyzerService, CookieSecurityService cookieSecurityService,
            RobotsTxtService robotsTxtService, DnsSecurityService dnsSecurityService,
            ScanHistoryService scanHistoryService, DomainProtectionService domainProtectionService,
            SensitiveFileService sensitiveFileService, HttpMethodService httpMethodService,
            SecurityTxtService securityTxtService, OpenRedirectService openRedirectService,
            DirectoryListingService directoryListingService) {
        this.sslService              = sslService;
        this.tlsVersionService       = tlsVersionService;
        this.headerService           = headerService;
        this.scoreService            = scoreService;
        this.httpFetchService        = httpFetchService;
        this.errorDisclosureService  = errorDisclosureService;
        this.portScanService         = portScanService;
        this.xssProbeService         = xssProbeService;
        this.wafDetectionService     = wafDetectionService;
        this.scanCacheService        = scanCacheService;
        this.corsAnalyzerService     = corsAnalyzerService;
        this.cookieSecurityService   = cookieSecurityService;
        this.robotsTxtService        = robotsTxtService;
        this.dnsSecurityService      = dnsSecurityService;
        this.scanHistoryService      = scanHistoryService;
        this.domainProtectionService = domainProtectionService;
        this.sensitiveFileService    = sensitiveFileService;
        this.httpMethodService       = httpMethodService;
        this.securityTxtService      = securityTxtService;
        this.openRedirectService     = openRedirectService;
        this.directoryListingService = directoryListingService;
    }

    public ScanResult execute(String url, boolean active, AppUser currentUser) {
        String inputUrl = normalizeUrl(url);
        String cacheKey = buildCacheKey(inputUrl, active);

        ScanResult cached = scanCacheService.get(cacheKey, ScanResult.class);
        if (cached != null) return cached;

        // ── Fase 1: infraestrutura — sequencial pois cada etapa depende da anterior
        String  httpsUrl      = toHttps(inputUrl);
        SSLInfo sslInfo       = sslService.checkSSL(httpsUrl);
        boolean supportsHttps = sslInfo.isHttps() && sslInfo.isValid();

        String     host       = extractHostSafe(httpsUrl);
        TlsDetails tlsDetails = (supportsHttps && host != null)
                ? tlsVersionService.inspect(host, 443)
                : new TlsDetails("N/A", "N/A", false, "HTTPS não disponível");

        boolean         redirectsToHttps = httpFetchService.traceRedirectToHttps(toHttp(inputUrl));
        String          analysisUrl      = supportsHttps ? httpsUrl : inputUrl;
        HttpFetchResult fetch            = httpFetchService.fetchHeaders(analysisUrl);

        Map<String, String> analyzedHeaders;
        boolean serverVersionExposed = false;
        if (fetch.getError() != null) {
            analyzedHeaders = Map.of("error", fetch.getError());
        } else {
            analyzedHeaders      = headerService.analyzeSecurityHeaders(fetch.getHeaders());
            serverVersionExposed = headerService.detectsServerVersionExposure(fetch.getHeaders());
        }

        String  target               = fetch.getFinalUrl() != null ? fetch.getFinalUrl() : analysisUrl;
        boolean inputSurfaceDetected = errorDisclosureService.hasQueryParams(target);

        // Cookies já vieram no fetch — sem request adicional
        List<CookieFinding> cookieIssues = cookieSecurityService.analyze(fetch.getRawSetCookies());

        // ── Fase 2: checks passivos independentes — PARALELOS ─────────────────
        ExecutorService pool = Executors.newFixedThreadPool(9);
        try {
            var corsFuture     = CompletableFuture.supplyAsync(
                            () -> corsAnalyzerService.analyze(target), pool)
                    .exceptionally(e -> null);

            var robotsFuture   = CompletableFuture.supplyAsync(
                            () -> robotsTxtService.findSensitivePaths(target), pool)
                    .exceptionally(e -> List.of());

            var filesFuture    = CompletableFuture.supplyAsync(
                            () -> sensitiveFileService.scan(target), pool)
                    .exceptionally(e -> List.of());

            var methodsFuture  = CompletableFuture.supplyAsync(
                            () -> httpMethodService.scan(target), pool)
                    .exceptionally(e -> List.of());

            var secTxtFuture   = CompletableFuture.supplyAsync(
                            () -> securityTxtService.check(target), pool)
                    .exceptionally(e -> null);

            var redirectFuture = CompletableFuture.supplyAsync(
                            () -> openRedirectService.scan(target, false), pool)
                    .exceptionally(e -> List.of());

            var dirListFuture  = CompletableFuture.supplyAsync(
                            () -> directoryListingService.scan(target), pool)
                    .exceptionally(e -> List.of());

            var dnsFuture      = CompletableFuture.supplyAsync(
                            () -> dnsSecurityService.scan(host), pool)
                    .exceptionally(e -> null);

            var wafFuture      = CompletableFuture.supplyAsync(
                            () -> wafDetectionService.scan(target), pool)
                    .exceptionally(e -> null);

            try {
                CompletableFuture.allOf(
                        corsFuture, robotsFuture, filesFuture, methodsFuture,
                        secTxtFuture, redirectFuture, dirListFuture, dnsFuture, wafFuture
                ).get(120, TimeUnit.SECONDS);
            } catch (Exception ignored) {
                // Timeout ou erro interno — continua com resultados parciais
                // getNow(default) retorna o default para futures não completados
            }

            // Coleta resultados com fallbacks seguros caso algum timeout
            CorsResult                 corsResult               = corsFuture.getNow(null);
            List<String>               sensitiveRobotsPaths    = robotsFuture.getNow(List.of());
            List<SensitiveFileFinding> sensitiveFiles          = filesFuture.getNow(List.of());
            List<HttpMethodFinding>    dangerousHttpMethods    = methodsFuture.getNow(List.of());
            List<OpenRedirectFinding>  openRedirectFindings    = redirectFuture.getNow(List.of());
            List<DirectoryListingFinding> directoryListingFindings = dirListFuture.getNow(List.of());
            DnsSecurityResult          dnsSecurityResult       = dnsFuture.getNow(null);
            WafDetectionResult         wafDetectionResult      = wafFuture.getNow(null);

            // SecurityTxt com null-safety
            SecurityTxtService.SecurityTxtResult securityTxt = secTxtFuture.getNow(null);
            boolean secTxtFound   = securityTxt != null && securityTxt.found();
            String  secTxtContact = securityTxt != null ? securityTxt.contact() : null;

            // ── Fase 3: score passivo ──────────────────────────────────────────
            ScoreResult passiveScore = scoreService.calculate(
                    sslInfo, tlsDetails, analyzedHeaders, redirectsToHttps,
                    false, inputSurfaceDetected, false, false, false, List.of(),
                    corsResult, cookieIssues, sensitiveRobotsPaths, serverVersionExposed,
                    sensitiveFiles, dangerousHttpMethods, secTxtFound,
                    openRedirectFindings, directoryListingFindings,
                    dnsSecurityResult, wafDetectionResult
            );

            ScanResult passiveResult = ScanResult.builder()
                    .url(inputUrl)
                    .finalUrl(fetch.getFinalUrl())
                    .httpStatus(fetch.getStatusCode())
                    .redirectsToHttps(redirectsToHttps)
                    .sslInfo(sslInfo)
                    .tlsDetails(tlsDetails)
                    .headers(analyzedHeaders)
                    .serverVersionExposed(serverVersionExposed)
                    .activeMode(false)
                    .inputSurfaceDetected(inputSurfaceDetected)
                    .dbErrorLeakageSuspected(false)
                    .xssProbePerformed(false)
                    .reflectedXssSuspected(false)
                    .openPorts(List.of())
                    .corsResult(corsResult)
                    .cookieIssues(cookieIssues)
                    .sensitiveRobotsPaths(sensitiveRobotsPaths)
                    .score(passiveScore)
                    .sensitiveFiles(sensitiveFiles)
                    .dangerousHttpMethods(dangerousHttpMethods)
                    .securityTxtPresent(secTxtFound)
                    .securityTxtContact(secTxtContact)
                    .openRedirectFindings(openRedirectFindings)
                    .directoryListingFindings(directoryListingFindings)
                    .dnsSecurityResult(dnsSecurityResult)
                    .wafDetectionResult(wafDetectionResult)
                    .build();

            // ── Fase 4: ownership check ────────────────────────────────────────
            if (active) {
                boolean needsOwnership  = domainProtectionService.requiresOwnershipForActiveScan(passiveResult);
                boolean bypassOwnership = currentUser != null &&
                        (currentUser.getRole() == Role.OWNER ||
                                currentUser.getRole() == Role.ADMIN);

                if (needsOwnership && !bypassOwnership &&
                        !domainProtectionService.isOwnershipVerified(host)) {
                    throw new OwnershipNotVerifiedException(passiveResult,
                            "Scan ativo não autorizado para este domínio. " +
                                    "Apenas o proprietário verificado pode executar scans ativos. " +
                                    "Acesse /scan/verify-token?host=" + host +
                                    " para obter as instruções de verificação.");
                }
            }

            // ── Fase 5: checks ativos ──────────────────────────────────────────
            boolean xssProbePerformed     = false;
            boolean reflectedXssSuspected = false;
            boolean dbErrorLeakage        = false;
            List<PortFinding>         openPorts       = List.of();
            List<OpenRedirectFinding> activeRedirects = openRedirectFindings;

            if (active) {
                if (inputSurfaceDetected) {
                    xssProbePerformed     = true;
                    reflectedXssSuspected = xssProbeService.reflectedMarkerAppears(target);
                    dbErrorLeakage        = errorDisclosureService.detectsDbErrorLeakage(target);
                    activeRedirects       = openRedirectService.scan(target, true);
                }
                if (host != null && !host.isBlank()) {
                    openPorts = portScanService.scanCommonPorts(host);
                }
            }

            // ── Fase 6: score final ────────────────────────────────────────────
            ScoreResult score = scoreService.calculate(
                    sslInfo, tlsDetails, analyzedHeaders, redirectsToHttps,
                    active, inputSurfaceDetected, dbErrorLeakage,
                    xssProbePerformed, reflectedXssSuspected, openPorts,
                    corsResult, cookieIssues, sensitiveRobotsPaths, serverVersionExposed,
                    sensitiveFiles, dangerousHttpMethods, secTxtFound,
                    activeRedirects, directoryListingFindings,
                    dnsSecurityResult, wafDetectionResult
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
                    .sensitiveFiles(sensitiveFiles)
                    .dangerousHttpMethods(dangerousHttpMethods)
                    .securityTxtPresent(secTxtFound)
                    .securityTxtContact(secTxtContact)
                    .openRedirectFindings(activeRedirects)
                    .directoryListingFindings(directoryListingFindings)
                    .dnsSecurityResult(dnsSecurityResult)
                    .wafDetectionResult(wafDetectionResult)
                    .build();

            scanCacheService.put(cacheKey, result);
            scanHistoryService.save(result);
            return result;

        } catch (OwnershipNotVerifiedException e) {
            throw e;
        } catch (Exception e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            throw new RuntimeException(
                    "Erro ao executar scan: " + cause.getClass().getSimpleName()
                            + (cause.getMessage() != null ? " — " + cause.getMessage() : ""), e);
        } finally {
            pool.shutdownNow();
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

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