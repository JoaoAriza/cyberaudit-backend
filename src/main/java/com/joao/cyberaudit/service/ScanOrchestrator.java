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
    private final TechFingerprintService  techFingerprintService;
    private final CVECorrelationService   cveCorrelationService;
    private final ScanChangeDetector          scanChangeDetector;
    private final SubdomainTakeoverService      subdomainTakeoverService;
    private final CertTransparencyService        certTransparencyService;
    private final CrtShService                  crtShService;             // ← compartilhado

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
            DirectoryListingService directoryListingService,
            TechFingerprintService techFingerprintService,
            CVECorrelationService cveCorrelationService,
            ScanChangeDetector scanChangeDetector,
            SubdomainTakeoverService subdomainTakeoverService,
            CertTransparencyService certTransparencyService,
            CrtShService crtShService) {                               // ← compartilhado
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
        this.techFingerprintService  = techFingerprintService;
        this.cveCorrelationService   = cveCorrelationService;
        this.scanChangeDetector         = scanChangeDetector;
        this.subdomainTakeoverService   = subdomainTakeoverService;
        this.certTransparencyService   = certTransparencyService;
        this.crtShService              = crtShService;            // ← compartilhado
    }

    public ScanResult execute(String url, boolean active, AppUser currentUser, boolean refresh) {
        String inputUrl = normalizeUrl(url);
        String cacheKey = buildCacheKey(inputUrl, active);

        if (!refresh) {
            ScanResult cached = scanCacheService.get(cacheKey, ScanResult.class);
            if (cached != null) return cached;
        } else {
            scanCacheService.invalidate(cacheKey);
        }

        // ── Fase 1: infraestrutura — sequencial ───────────────────────────────
        String  httpsUrl      = toHttps(inputUrl);
        SSLInfo sslInfo       = sslService.checkSSL(httpsUrl);
        boolean supportsHttps = sslInfo.isHttps() && sslInfo.isValid();

        String     host       = extractHostSafe(httpsUrl);
        TlsDetails tlsDetails = (supportsHttps && host != null)
                ? tlsVersionService.inspect(host, 443)
                : new TlsDetails("N/A", "N/A", false, "HTTPS não disponível");

        boolean redirectsToHttps = httpFetchService.traceRedirectToHttps(toHttp(inputUrl));

        String analysisUrl;
        if (supportsHttps)          analysisUrl = httpsUrl;
        else if (sslInfo.isHttps()) analysisUrl = toHttp(inputUrl);
        else                        analysisUrl = toHttp(inputUrl);

        HttpFetchResult fetch = httpFetchService.fetchHeaders(analysisUrl);

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
        List<CookieFinding> cookieIssues = cookieSecurityService.analyze(fetch.getRawSetCookies());

        // ── Fase 1b: fingerprint + CVE (paralelo) ─────────────────────────────
        ExecutorService fingerprintPool = Executors.newFixedThreadPool(2);

        var fingerprintFuture = CompletableFuture.supplyAsync(
                () -> techFingerprintService.fingerprint(target, analyzedHeaders, fetch.getRawSetCookies()),
                fingerprintPool).exceptionally(e -> null);

        var cveFuture = fingerprintFuture.thenApplyAsync(
                fp -> fp != null ? cveCorrelationService.correlate(fp) : List.<CVEFinding>of(),
                fingerprintPool);

        // ── Busca scan anterior ANTES de salvar (para change detection) ───────
        ScanResult previousScan = (host != null)
                ? scanHistoryService.findLastResult(host, active).orElse(null)
                : null;

        // ── Fase 2: checks passivos — PARALELOS ───────────────────────────────
        ExecutorService passivePool = Executors.newFixedThreadPool(8);
        try {
            var robotsFuture = CompletableFuture.supplyAsync(
                            () -> robotsTxtService.findSensitivePaths(target), passivePool)
                    .exceptionally(e -> List.of());
            var secTxtFuture = CompletableFuture.supplyAsync(
                            () -> securityTxtService.check(target), passivePool)
                    .exceptionally(e -> null);
            var dnsFuture = CompletableFuture.supplyAsync(
                            () -> dnsSecurityService.scan(host), passivePool)
                    .exceptionally(e -> null);
            var methodsFuture = CompletableFuture.supplyAsync(
                            () -> httpMethodService.scan(target), passivePool)
                    .exceptionally(e -> List.of());
            var dirListFuture = CompletableFuture.supplyAsync(
                            () -> directoryListingService.scan(target), passivePool)
                    .exceptionally(e -> List.of());

            var takeoverFuture = CompletableFuture.supplyAsync(
                            () -> subdomainTakeoverService.scan(target), passivePool)
                    .exceptionally(e -> List.of());

            // CT encadeado após DNS para garantir que recebe o resultado correto
            var certTransFuture = dnsFuture
                    .thenApplyAsync(
                            dnsResult -> certTransparencyService.scan(host, dnsResult),
                            passivePool)
                    .exceptionally(e -> null);

            try {
                CompletableFuture.allOf(
                        robotsFuture, secTxtFuture, dnsFuture, methodsFuture, dirListFuture,
                        takeoverFuture, certTransFuture, cveFuture
                ).get(120, TimeUnit.SECONDS);
            } catch (Exception ignored) {}

            fingerprintPool.shutdownNow();

            List<String>                  sensitiveRobotsPaths     = robotsFuture.getNow(List.of());
            List<HttpMethodFinding>       dangerousHttpMethods     = methodsFuture.getNow(List.of());
            List<DirectoryListingFinding> directoryListingFindings = dirListFuture.getNow(List.of());
            DnsSecurityResult             dnsSecurityResult        = dnsFuture.getNow(null);
            TechFingerprintResult             techFingerprint      = fingerprintFuture.getNow(null);
            List<SubdomainTakeoverFinding>    takeoverFindings     = takeoverFuture.getNow(List.of());
            CertTransparencyResult               certTransparency     = certTransFuture.getNow(null);
            List<CVEFinding>              cveFindings              = cveFuture.getNow(List.of());

            SecurityTxtService.SecurityTxtResult securityTxt = secTxtFuture.getNow(null);
            boolean secTxtFound   = securityTxt != null && securityTxt.found();
            String  secTxtContact = securityTxt != null ? securityTxt.contact() : null;

            ScoreResult passiveScore = scoreService.calculate(
                    sslInfo, tlsDetails, analyzedHeaders, redirectsToHttps,
                    false, inputSurfaceDetected, false, false, false, List.of(),
                    null, cookieIssues, sensitiveRobotsPaths, serverVersionExposed,
                    List.of(), dangerousHttpMethods, secTxtFound,
                    List.of(), directoryListingFindings, dnsSecurityResult, null,
                    cveFindings
            );

            // ── Monta resultado passivo ────────────────────────────────────────
            ScanResult passiveResult = ScanResult.builder()
                    .url(inputUrl).finalUrl(fetch.getFinalUrl())
                    .httpStatus(fetch.getStatusCode())
                    .redirectsToHttps(redirectsToHttps)
                    .sslInfo(sslInfo).tlsDetails(tlsDetails)
                    .headers(analyzedHeaders).serverVersionExposed(serverVersionExposed)
                    .activeMode(false).inputSurfaceDetected(inputSurfaceDetected)
                    .dbErrorLeakageSuspected(false).xssProbePerformed(false)
                    .reflectedXssSuspected(false).openPorts(List.of())
                    .corsResult(null).cookieIssues(cookieIssues)
                    .sensitiveRobotsPaths(sensitiveRobotsPaths).sensitiveFiles(List.of())
                    .dangerousHttpMethods(dangerousHttpMethods)
                    .securityTxtPresent(secTxtFound).securityTxtContact(secTxtContact)
                    .openRedirectFindings(List.of())
                    .directoryListingFindings(directoryListingFindings)
                    .dnsSecurityResult(dnsSecurityResult).wafDetectionResult(null)
                    .techFingerprint(techFingerprint).cveFindings(cveFindings)
                    .subdomainTakeover(takeoverFindings)
                    .certTransparency(certTransparency)            // ← novo
                    .changes(scanChangeDetector.detect(
                            buildPartialForDiff(passiveScore, sslInfo, analyzedHeaders,
                                    serverVersionExposed, dangerousHttpMethods, List.of(),
                                    dnsSecurityResult, null, techFingerprint, List.of()),
                            previousScan))                             // ← change detection
                    .score(passiveScore)
                    .build();

            // ── Fase 3: ownership check ────────────────────────────────────────
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

            if (!active) {
                scanCacheService.put(cacheKey, passiveResult);
                scanHistoryService.save(passiveResult);
                return passiveResult;
            }

            // ── Fase 4: checks ativos — PARALELOS ─────────────────────────────
            ExecutorService activePool = Executors.newFixedThreadPool(6);

            var corsFuture     = CompletableFuture.supplyAsync(
                    () -> corsAnalyzerService.analyze(target), activePool).exceptionally(e -> null);
            var filesFuture    = CompletableFuture.supplyAsync(
                    () -> sensitiveFileService.scan(target), activePool).exceptionally(e -> List.of());
            var wafFuture      = CompletableFuture.supplyAsync(
                    () -> wafDetectionService.scan(target), activePool).exceptionally(e -> null);
            var redirectFuture = CompletableFuture.supplyAsync(
                    () -> openRedirectService.scan(target, true), activePool).exceptionally(e -> List.of());
            var xssFuture = inputSurfaceDetected
                    ? CompletableFuture.supplyAsync(() -> xssProbeService.reflectedMarkerAppears(target), activePool).exceptionally(e -> false)
                    : CompletableFuture.completedFuture(false);
            var dbFuture = inputSurfaceDetected
                    ? CompletableFuture.supplyAsync(() -> errorDisclosureService.detectsDbErrorLeakage(target), activePool).exceptionally(e -> false)
                    : CompletableFuture.completedFuture(false);
            var portFuture = (host != null && !host.isBlank())
                    ? CompletableFuture.supplyAsync(() -> portScanService.scanCommonPorts(host), activePool).exceptionally(e -> List.of())
                    : CompletableFuture.completedFuture(List.<PortFinding>of());

            try {
                CompletableFuture.allOf(
                        corsFuture, filesFuture, wafFuture, redirectFuture,
                        xssFuture, dbFuture, portFuture
                ).get(120, TimeUnit.SECONDS);
            } catch (Exception ignored) {}

            activePool.shutdownNow();

            CorsResult                 corsResult            = corsFuture.getNow(null);
            List<SensitiveFileFinding> sensitiveFiles        = filesFuture.getNow(List.of());
            WafDetectionResult         wafDetectionResult    = wafFuture.getNow(null);
            List<OpenRedirectFinding>  openRedirectFindings  = redirectFuture.getNow(List.of());
            boolean xssProbePerformed     = inputSurfaceDetected;
            boolean reflectedXssSuspected = xssFuture.getNow(false);
            boolean dbErrorLeakage        = dbFuture.getNow(false);
            List<PortFinding> openPorts   = portFuture.getNow(List.of());

            ScoreResult score = scoreService.calculate(
                    sslInfo, tlsDetails, analyzedHeaders, redirectsToHttps,
                    true, inputSurfaceDetected, dbErrorLeakage,
                    xssProbePerformed, reflectedXssSuspected, openPorts,
                    corsResult, cookieIssues, sensitiveRobotsPaths, serverVersionExposed,
                    sensitiveFiles, dangerousHttpMethods, secTxtFound,
                    openRedirectFindings, directoryListingFindings,
                    dnsSecurityResult, wafDetectionResult, cveFindings
            );

            ScanResult result = ScanResult.builder()
                    .url(inputUrl).finalUrl(fetch.getFinalUrl())
                    .httpStatus(fetch.getStatusCode())
                    .redirectsToHttps(redirectsToHttps)
                    .sslInfo(sslInfo).tlsDetails(tlsDetails)
                    .headers(analyzedHeaders).serverVersionExposed(serverVersionExposed)
                    .activeMode(true).inputSurfaceDetected(inputSurfaceDetected)
                    .dbErrorLeakageSuspected(dbErrorLeakage)
                    .xssProbePerformed(xssProbePerformed)
                    .reflectedXssSuspected(reflectedXssSuspected)
                    .openPorts(openPorts).corsResult(corsResult)
                    .cookieIssues(cookieIssues)
                    .sensitiveRobotsPaths(sensitiveRobotsPaths).sensitiveFiles(sensitiveFiles)
                    .dangerousHttpMethods(dangerousHttpMethods)
                    .securityTxtPresent(secTxtFound).securityTxtContact(secTxtContact)
                    .openRedirectFindings(openRedirectFindings)
                    .directoryListingFindings(directoryListingFindings)
                    .dnsSecurityResult(dnsSecurityResult).wafDetectionResult(wafDetectionResult)
                    .techFingerprint(techFingerprint).cveFindings(cveFindings)
                    .subdomainTakeover(takeoverFindings)
                    .certTransparency(certTransparency)
                    .changes(scanChangeDetector.detect(              // ← change detection
                            buildPartialForDiff(score, sslInfo, analyzedHeaders,
                                    serverVersionExposed, dangerousHttpMethods, openPorts,
                                    dnsSecurityResult, wafDetectionResult, techFingerprint, sensitiveFiles),
                            previousScan))
                    .score(score)
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
            passivePool.shutdownNow();
        }
    }

    /**
     * Monta um ScanResult parcial só para diff — não inclui campos
     * que não existem neste ponto (ex: corsResult no passivo).
     */
    private ScanResult buildPartialForDiff(
            ScoreResult score, SSLInfo sslInfo, Map<String, String> headers,
            boolean serverVersionExposed, List<HttpMethodFinding> methods,
            List<PortFinding> ports, DnsSecurityResult dns,
            WafDetectionResult waf, TechFingerprintResult tech,
            List<SensitiveFileFinding> files) {
        return ScanResult.builder()
                .score(score).sslInfo(sslInfo).headers(headers)
                .serverVersionExposed(serverVersionExposed)
                .dangerousHttpMethods(methods).openPorts(ports)
                .dnsSecurityResult(dns).wafDetectionResult(waf)
                .techFingerprint(tech).sensitiveFiles(files)
                .build();
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
    private static final String CACHE_VERSION = "v3";
    private String buildCacheKey(String url, boolean active) {
        String h = extractHostSafe(url);
        return CACHE_VERSION + ":scan:" + (h != null ? h : url) + ":active=" + active;
    }
}