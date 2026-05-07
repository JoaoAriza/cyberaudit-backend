package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.*;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.util.List;
import java.util.Map;

/**
 * Contém toda a lógica de execução de um scan.
 * Extraído do ScanController para poder ser chamado tanto
 * pelo endpoint síncrono quanto pelo assíncrono.
 */
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
    private final ScanCacheService       scanCacheService;
    private final CorsAnalyzerService    corsAnalyzerService;
    private final CookieSecurityService  cookieSecurityService;
    private final RobotsTxtService       robotsTxtService;
    private final ScanHistoryService     scanHistoryService;

    public ScanOrchestrator(
            SSLService sslService,
            TlsVersionService tlsVersionService,
            HeaderService headerService,
            ScoreService scoreService,
            HttpFetchService httpFetchService,
            ErrorDisclosureService errorDisclosureService,
            PortScanService portScanService,
            XssProbeService xssProbeService,
            ScanCacheService scanCacheService,
            CorsAnalyzerService corsAnalyzerService,
            CookieSecurityService cookieSecurityService,
            RobotsTxtService robotsTxtService,
            ScanHistoryService scanHistoryService
    ) {
        this.sslService             = sslService;
        this.tlsVersionService      = tlsVersionService;
        this.headerService          = headerService;
        this.scoreService           = scoreService;
        this.httpFetchService       = httpFetchService;
        this.errorDisclosureService = errorDisclosureService;
        this.portScanService        = portScanService;
        this.xssProbeService        = xssProbeService;
        this.scanCacheService       = scanCacheService;
        this.corsAnalyzerService    = corsAnalyzerService;
        this.cookieSecurityService  = cookieSecurityService;
        this.robotsTxtService       = robotsTxtService;
        this.scanHistoryService     = scanHistoryService;
    }

    public ScanResult execute(String url, boolean active) {
        String inputUrl = normalizeUrl(url);
        String cacheKey = buildCacheKey(inputUrl, active);

        ScanResult cached = scanCacheService.get(cacheKey, ScanResult.class);
        if (cached != null) return cached;

        String  httpsUrl      = toHttps(inputUrl);
        SSLInfo sslInfo       = sslService.checkSSL(httpsUrl);
        boolean supportsHttps = sslInfo.isHttps() && sslInfo.isValid();

        String     host       = extractHostSafe(httpsUrl);
        TlsDetails tlsDetails = (supportsHttps && host != null)
                ? tlsVersionService.inspect(host, 443)
                : new TlsDetails("N/A", "N/A", false, "HTTPS não disponível");

        boolean redirectsToHttps = httpFetchService.traceRedirectToHttps(toHttp(inputUrl));

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

        CorsResult corsResult = corsAnalyzerService.analyze(target);

        List<CookieFinding> cookieIssues = cookieSecurityService.analyze(fetch.getRawSetCookies());

        List<String> sensitiveRobotsPaths = robotsTxtService.findSensitivePaths(target);

        boolean inputSurfaceDetected = errorDisclosureService.hasQueryParams(target);

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