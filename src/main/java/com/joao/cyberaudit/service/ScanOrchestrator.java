package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.*;
import com.joao.cyberaudit.exception.OwnershipNotVerifiedException;
import org.checkerframework.common.returnsreceiver.qual.This;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.util.List;
import java.util.Map;

@Service
public class ScanOrchestrator {

    private final SSLService             sslService;
    private final TlsVersionService      tlsVersionService;
    private final HeaderService          headerService;
    private final ScoreService           scoreService;
    private final HttpFetchService       httpFetchService;
    private final ErrorDisclosureService errorDisclosureService;
    private final PortScanService        portScanService;
    private final XssProbeService        xssProbeService;
    private final WafDetectionService     wafDetectionService;
    private final ScanCacheService       scanCacheService;
    private final CorsAnalyzerService    corsAnalyzerService;
    private final CookieSecurityService  cookieSecurityService;
    private final RobotsTxtService       robotsTxtService;
    private final DnsSecurityService      dnsSecurityService;
    private final ScanHistoryService     scanHistoryService;
    private final DomainProtectionService domainProtectionService;
    private final SensitiveFileService   sensitiveFileService;
    private final HttpMethodService      httpMethodService;
    private final SecurityTxtService     securityTxtService;
    private final OpenRedirectService    openRedirectService;
    private final DirectoryListingService directoryListingService;

    public ScanOrchestrator(
            SSLService sslService,
            TlsVersionService tlsVersionService,
            HeaderService headerService,
            ScoreService scoreService,
            HttpFetchService httpFetchService,
            ErrorDisclosureService errorDisclosureService,
            PortScanService portScanService,
            XssProbeService xssProbeService,
            WafDetectionService wafDetectionService,
            ScanCacheService scanCacheService,
            CorsAnalyzerService corsAnalyzerService,
            CookieSecurityService cookieSecurityService,
            RobotsTxtService robotsTxtService,
            DnsSecurityService dnsSecurityService,
            ScanHistoryService scanHistoryService,
            DomainProtectionService domainProtectionService,
            SensitiveFileService sensitiveFileService,
            HttpMethodService httpMethodService,
            SecurityTxtService securityTxtService,
            OpenRedirectService openRedirectService,
            DirectoryListingService directoryListingService
    ) {
        this.sslService             = sslService;
        this.tlsVersionService      = tlsVersionService;
        this.headerService          = headerService;
        this.scoreService           = scoreService;
        this.httpFetchService       = httpFetchService;
        this.errorDisclosureService = errorDisclosureService;
        this.portScanService        = portScanService;
        this.xssProbeService        = xssProbeService;
        this.wafDetectionService    = wafDetectionService;
        this.scanCacheService       = scanCacheService;
        this.corsAnalyzerService    = corsAnalyzerService;
        this.cookieSecurityService  = cookieSecurityService;
        this.robotsTxtService       = robotsTxtService;
        this.dnsSecurityService     = dnsSecurityService;
        this.scanHistoryService     = scanHistoryService;
        this.domainProtectionService = domainProtectionService;
        this.sensitiveFileService = sensitiveFileService;
        this.httpMethodService    = httpMethodService;
        this.securityTxtService   = securityTxtService;
        this.openRedirectService      = openRedirectService;
        this.directoryListingService  = directoryListingService;
    }

    public ScanResult execute(String url, boolean active, AppUser currentUser) {
        String inputUrl  = normalizeUrl(url);
        String cacheKey  = buildCacheKey(inputUrl, active);

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
        List<CookieFinding> cookieIssues = cookieSecurityService.analyze(
                fetch.getRawSetCookies());

        // ── 7. robots.txt ───────────────────────────────────
        List<String> sensitiveRobotsPaths = robotsTxtService.findSensitivePaths(target);

        // ── 8. Superfície de entrada (passivo) ───────────────
        boolean inputSurfaceDetected = errorDisclosureService.hasQueryParams(target);

        // ── 8b. Novos checks passivos ────────────────────────
        List<SensitiveFileFinding> sensitiveFiles =
                sensitiveFileService.scan(target);

        List<HttpMethodFinding> dangerousHttpMethods =
                httpMethodService.scan(target);

        SecurityTxtService.SecurityTxtResult securityTxt =
                securityTxtService.check(target);

        List<OpenRedirectFinding> openRedirectFindings =
                openRedirectService.scan(target, false); // passivo por padrão

        List<DirectoryListingFinding> directoryListingFindings =
                directoryListingService.scan(target);

        DnsSecurityResult dnsSecurityResult = dnsSecurityService.scan(host);

        WafDetectionResult wafDetectionResult = wafDetectionService.scan(target);

        //Score passivo parcial ─────────────────────────
        // Calculamos o score passivo antes de decidir se o ativo roda.
        // Isso permite que requiresOwnershipForActiveScan analise o resultado.
        ScoreResult passiveScore = scoreService.calculate(
                sslInfo, tlsDetails, analyzedHeaders, redirectsToHttps,
                false, inputSurfaceDetected, false,
                false, false, List.of(),
                corsResult, cookieIssues, sensitiveRobotsPaths, serverVersionExposed,
                sensitiveFiles, dangerousHttpMethods, securityTxt.found(), openRedirectFindings,
                directoryListingFindings, dnsSecurityResult, wafDetectionResult
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
                .securityTxtPresent(securityTxt.found())
                .securityTxtContact(securityTxt.contact())
                .openRedirectFindings(openRedirectFindings)
                .directoryListingFindings(directoryListingFindings)
                .dnsSecurityResult(dnsSecurityResult)
                .wafDetectionResult(wafDetectionResult)
                .build();

        if (active) {
            boolean needsOwnership = domainProtectionService
                    .requiresOwnershipForActiveScan(passiveResult);

            if (needsOwnership && !domainProtectionService.isOwnershipVerified(host)) {
                throw new OwnershipNotVerifiedException(
                        passiveResult,
                        "Scan ativo não autorizado para este domínio. " +
                                "Apenas o proprietário verificado pode executar scans ativos. " +
                                "Acesse /scan/verify-token?host=" + host + " para obter as instruções de verificação."
                );
            }
        }

        boolean xssProbePerformed     = false;
        boolean reflectedXssSuspected = false;
        boolean dbErrorLeakage        = false;
        List<PortFinding> openPorts   = List.of();

        if (active) {
            if (inputSurfaceDetected) {
                xssProbePerformed     = true;
                reflectedXssSuspected = xssProbeService.reflectedMarkerAppears(target);
                dbErrorLeakage        = errorDisclosureService.detectsDbErrorLeakage(target);
                openRedirectFindings  = openRedirectService.scan(target, true);
            }
            if (host != null && !host.isBlank()) {
                openPorts = portScanService.scanCommonPorts(host);
            }
        }

        ScoreResult score = scoreService.calculate(
                sslInfo, tlsDetails, analyzedHeaders, redirectsToHttps,
                active, inputSurfaceDetected, dbErrorLeakage,
                xssProbePerformed, reflectedXssSuspected, openPorts,
                corsResult, cookieIssues, sensitiveRobotsPaths, serverVersionExposed,
                sensitiveFiles, dangerousHttpMethods, securityTxt.found(), openRedirectFindings,
                directoryListingFindings, dnsSecurityResult, wafDetectionResult
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
                .securityTxtPresent(securityTxt.found())
                .securityTxtContact(securityTxt.contact())
                .openRedirectFindings(openRedirectFindings)
                .directoryListingFindings(directoryListingFindings)
                .dnsSecurityResult(dnsSecurityResult)
                .wafDetectionResult(wafDetectionResult)
                .build();

        scanCacheService.put(cacheKey, result);
        scanHistoryService.save(result);
        return result;
    }


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