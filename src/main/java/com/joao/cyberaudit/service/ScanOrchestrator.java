package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.*;
import java.util.Collections;
import com.joao.cyberaudit.exception.DomainBlockedException;
import com.joao.cyberaudit.exception.OwnershipNotVerifiedException;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
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
    private final ApiDocsExposureService         apiDocsExposureService;
    private final PathTraversalService           pathTraversalService;
    private final GraphQlIntrospectionService    graphQlIntrospectionService;
    private final JwtSecurityService             jwtSecurityService;
    private final SsrfService                    ssrfService;
    private final HostHeaderService              hostHeaderService;
    private final SourceMapService               sourceMapService;
    private final CrlfService                    crlfService;
    private final AuditService                   auditService;
    private final DegradationNotificationService degradationNotificationService;
    private final ComplianceMappingService        complianceMappingService;
    private final RelatedHostsHeaderService       relatedHostsHeaderService;
    private final ScanConcurrencyLimiter          concurrencyLimiter;
    private final PlatformStaffService            platformStaffService;
    private final HostingProviderPolicy           hostingProviderPolicy;

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
            CrtShService crtShService,                               // ← compartilhado
            ApiDocsExposureService apiDocsExposureService,
            PathTraversalService pathTraversalService,
            GraphQlIntrospectionService graphQlIntrospectionService,
            JwtSecurityService jwtSecurityService,
            SsrfService ssrfService,
            HostHeaderService hostHeaderService,
            SourceMapService sourceMapService,
            CrlfService crlfService,
            AuditService auditService,
            DegradationNotificationService degradationNotificationService,
            ComplianceMappingService complianceMappingService,
            RelatedHostsHeaderService relatedHostsHeaderService,
            ScanConcurrencyLimiter concurrencyLimiter,
            PlatformStaffService platformStaffService,
            HostingProviderPolicy hostingProviderPolicy) {
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
        this.apiDocsExposureService    = apiDocsExposureService;
        this.pathTraversalService      = pathTraversalService;
        this.graphQlIntrospectionService = graphQlIntrospectionService;
        this.jwtSecurityService          = jwtSecurityService;
        this.ssrfService                 = ssrfService;
        this.hostHeaderService           = hostHeaderService;
        this.sourceMapService            = sourceMapService;
        this.crlfService                        = crlfService;
        this.auditService                       = auditService;
        this.degradationNotificationService     = degradationNotificationService;
        this.complianceMappingService           = complianceMappingService;
        this.relatedHostsHeaderService          = relatedHostsHeaderService;
        this.concurrencyLimiter                 = concurrencyLimiter;
        this.platformStaffService               = platformStaffService;
        this.hostingProviderPolicy              = hostingProviderPolicy;
    }

    public ScanResult execute(String url, boolean active, AppUser currentUser, boolean refresh) {
        return execute(url, active, currentUser, refresh, ScanOrigin.MANUAL);
    }

    public ScanResult execute(String url, boolean active, AppUser currentUser, boolean refresh, ScanOrigin origin) {
        return execute(url, active, currentUser, refresh, origin, ScanProgress.desligado());
    }

    /**
     * Variante que reporta o andamento enquanto trabalha.
     *
     * O {@code progresso} é parâmetro, e não campo, porque este serviço é singleton
     * e atende vários scans ao mesmo tempo — um campo misturaria o progresso de
     * clientes diferentes. Quem não observa passa {@link ScanProgress#desligado()},
     * que é o que as três outras assinaturas fazem.
     */
    public ScanResult execute(String url, boolean active, AppUser currentUser, boolean refresh,
                              ScanOrigin origin, ScanProgress progresso) {
        String inputUrl = normalizeUrl(url);
        // Anti-SSRF: bloqueia alvos internos/privados antes de qualquer request
        // (cobre fetch, port scan e demais módulos, pois todos rodam dentro deste execute()).
        SsrfGuard.validate(inputUrl);

        // Infraestrutura de quem nos hospeda nunca é alvo legítimo — o suporte do
        // Render pediu explicitamente que o scanner não sonde os sistemas deles.
        String targetHost = extractHostSafe(inputUrl);
        if (hostingProviderPolicy.isProviderInfrastructure(targetHost)) {
            throw new DomainBlockedException(
                    "Scan bloqueado: '" + targetHost + "' é infraestrutura do provedor de "
                            + "hospedagem desta plataforma e não pode ser escaneado daqui.");
        }
        String cacheKey = buildCacheKey(inputUrl, active);

        if (!refresh) {
            ScanResult cached = scanCacheService.get(cacheKey, ScanResult.class);
            if (cached != null) return cached;
        } else {
            scanCacheService.invalidate(cacheKey);
        }

        // Só o trabalho real ocupa slot — cache hit não entra na fila.
        final AppUser user = currentUser;
        return concurrencyLimiter.withSlot(
                () -> runScan(inputUrl, cacheKey, active, user, origin, progresso));
    }

    private ScanResult runScan(String inputUrl, String cacheKey, boolean active,
                               AppUser currentUser, ScanOrigin origin, ScanProgress progresso) {
        // Registra início do scan somente para usuários autenticados
        if (currentUser != null) {
            auditService.log(currentUser, AuditAction.SCAN_STARTED,
                    (active ? "active" : "passive") + " — " + inputUrl);
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

        // Primeira requisição ao alvo e a mais lenta a aparecer: marcada à mão porque
        // roda fora dos pools, e sem ela o feed ficaria vazio justamente no começo.
        progresso.registra(ScanCheck.HTTP_FETCH, ScanProgress.Estado.RODANDO);
        HttpFetchResult fetch = httpFetchService.fetchHeaders(analysisUrl);
        progresso.registra(ScanCheck.HTTP_FETCH,
                fetch.getError() != null ? ScanProgress.Estado.FALHOU : ScanProgress.Estado.OK);

        Map<String, String> analyzedHeaders;
        boolean serverVersionExposed = false;
        if (fetch.getError() != null) {
            analyzedHeaders = Map.of("error", fetch.getError());
        } else {
            analyzedHeaders      = headerService.analyzeSecurityHeaders(fetch.getHeaders());
            serverVersionExposed = headerService.detectsServerVersionExposure(fetch.getHeaders());
        }

        String  target               = fetch.getFinalUrl() != null ? fetch.getFinalUrl() : analysisUrl;
        // Host de onde os headers vieram de fato (após redirects) — explicitado no resultado
        // para deixar claro "de qual host são estes headers" (vs. subdomínios de API).
        String  analyzedHost         = extractHostSafe(target);
        if (analyzedHost == null) analyzedHost = host;
        boolean inputSurfaceDetected = errorDisclosureService.hasQueryParams(target);
        List<CookieFinding> cookieIssues = cookieSecurityService.analyze(fetch.getRawSetCookies());
        // JWT analysis: passivo, usa cookies ja obtidos — sem request adicional
        List<JwtSecurityFinding> jwtSecurity = jwtSecurityService.analyze(
                fetch.getRawSetCookies(), fetch.getHeaders());

        // ── Fase 1b: fingerprint + CVE (paralelo) ─────────────────────────────
        ExecutorService fingerprintPool = Executors.newFixedThreadPool(2);

        var fingerprintFuture = CompletableFuture.supplyAsync(
                progresso.acompanha(ScanCheck.TECH_FINGERPRINT,
                        () -> techFingerprintService.fingerprint(target, analyzedHeaders, fetch.getRawSetCookies())),
                fingerprintPool).exceptionally(e -> null);

        // Encadeada, não paralela: `acompanha` embrulha o corpo porque quem chega
        // aqui é uma Function, e o que interessa marcar é a correlação em si.
        var cveFuture = fingerprintFuture.thenApplyAsync(
                fp -> progresso.acompanha(ScanCheck.CVE,
                        () -> fp != null ? cveCorrelationService.correlate(fp) : List.<CVEFinding>of()).get(),
                fingerprintPool);

        // ── Busca scan anterior ANTES de salvar (para change detection) ───────
        ScanResult previousScan = (host != null)
                ? scanHistoryService.findLastResult(host, active,
                        currentUser != null ? currentUser.getAccount() : null).orElse(null)
                : null;

        // ── Fase 2: checks passivos — PARALELOS ───────────────────────────────
        ExecutorService passivePool = Executors.newFixedThreadPool(8);
        // Status por módulo — distingue "verificado" de "não concluído" (ver moduleState).
        Map<String, String> moduleStatus = new LinkedHashMap<>();
        // Fetch principal já rodou na fase 1: erro aqui = headers não verificados (vide ScoreService).
        moduleStatus.put(ScanCheck.HTTP_FETCH.name(), fetch.getError() != null ? "ERROR" : "OK");
        try {
            var robotsFuture = CompletableFuture.supplyAsync(
                            progresso.acompanha(ScanCheck.ROBOTS,
                                    () -> robotsTxtService.findSensitivePaths(target)), passivePool)
                    .exceptionally(e -> List.of());
            var secTxtFuture = CompletableFuture.supplyAsync(
                            progresso.acompanha(ScanCheck.SECURITY_TXT,
                                    () -> securityTxtService.check(target)), passivePool)
                    .exceptionally(e -> null);
            var dnsFuture = CompletableFuture.supplyAsync(
                            progresso.acompanha(ScanCheck.DNS_EMAIL,
                                    () -> dnsSecurityService.scan(host)), passivePool)
                    .exceptionally(e -> null);
            var methodsFuture = CompletableFuture.supplyAsync(
                            progresso.acompanha(ScanCheck.HTTP_METHODS,
                                    () -> httpMethodService.scan(target)), passivePool)
                    .exceptionally(e -> List.of());
            var dirListFuture = CompletableFuture.supplyAsync(
                            progresso.acompanha(ScanCheck.DIRECTORY_LISTING,
                                    () -> directoryListingService.scan(target)), passivePool)
                    .exceptionally(e -> List.of());

            var takeoverFuture = CompletableFuture.supplyAsync(
                            progresso.acompanha(ScanCheck.SUBDOMAIN_TAKEOVER,
                                    () -> subdomainTakeoverService.scan(target)), passivePool)
                    .exceptionally(e -> List.of());
            var sourceMapFuture = CompletableFuture.supplyAsync(
                    progresso.acompanha(ScanCheck.SOURCE_MAPS,
                            () -> sourceMapService.scan(target)), passivePool).exceptionally(e -> List.of());
            var hostHeaderFuture = CompletableFuture.supplyAsync(
                    progresso.acompanha(ScanCheck.HOST_HEADER,
                            () -> hostHeaderService.scan(target)), passivePool).exceptionally(e -> List.of());
            var apiDocsFuture  = CompletableFuture.supplyAsync(
                            progresso.acompanha(ScanCheck.API_DOCS,
                                    () -> apiDocsExposureService.scan(target)), passivePool)
                    .exceptionally(e -> List.of());
            var graphQlFuture  = CompletableFuture.supplyAsync(
                            progresso.acompanha(ScanCheck.GRAPHQL,
                                    () -> graphQlIntrospectionService.scan(target)), passivePool)
                    .exceptionally(e -> List.of());
            var relatedHostsFuture = CompletableFuture.supplyAsync(
                            progresso.acompanha(ScanCheck.RELATED_HOSTS,
                                    () -> relatedHostsHeaderService.analyze(host)), passivePool)
                    .exceptionally(e -> List.<RelatedHostHeaders>of());

            // CT encadeado após DNS para garantir que recebe o resultado correto
            var certTransFuture = dnsFuture
                    .thenApplyAsync(
                            dnsResult -> progresso.acompanha(ScanCheck.CERT_TRANSPARENCY,
                                    () -> certTransparencyService.scan(host, dnsResult)).get(),
                            passivePool)
                    .exceptionally(e -> null);

            try {
                CompletableFuture.allOf(
                        robotsFuture, secTxtFuture, dnsFuture, methodsFuture, dirListFuture,
                        hostHeaderFuture, sourceMapFuture,
                        takeoverFuture, certTransFuture, cveFuture, apiDocsFuture, graphQlFuture,
                        relatedHostsFuture
                ).get(120, TimeUnit.SECONDS);
            } catch (Exception ignored) {}

            fingerprintPool.shutdownNow();

            // ── Status dos módulos passivos ───────────────────────────────────
            moduleStatus.put(ScanCheck.ROBOTS.name(),            moduleState(robotsFuture));
            moduleStatus.put(ScanCheck.SECURITY_TXT.name(),      moduleState(secTxtFuture));
            moduleStatus.put(ScanCheck.DNS_EMAIL.name(),         moduleState(dnsFuture));
            moduleStatus.put(ScanCheck.HTTP_METHODS.name(),      moduleState(methodsFuture));
            moduleStatus.put(ScanCheck.DIRECTORY_LISTING.name(), moduleState(dirListFuture));
            moduleStatus.put(ScanCheck.SUBDOMAIN_TAKEOVER.name(),moduleState(takeoverFuture));
            moduleStatus.put(ScanCheck.SOURCE_MAPS.name(),       moduleState(sourceMapFuture));
            moduleStatus.put(ScanCheck.HOST_HEADER.name(),       moduleState(hostHeaderFuture));
            moduleStatus.put(ScanCheck.API_DOCS.name(),          moduleState(apiDocsFuture));
            moduleStatus.put(ScanCheck.GRAPHQL.name(),           moduleState(graphQlFuture));
            moduleStatus.put(ScanCheck.CERT_TRANSPARENCY.name(),moduleState(certTransFuture));
            moduleStatus.put(ScanCheck.TECH_FINGERPRINT.name(), moduleState(fingerprintFuture));
            moduleStatus.put(ScanCheck.CVE.name(),               moduleState(cveFuture));
            moduleStatus.put(ScanCheck.RELATED_HOSTS.name(),     moduleState(relatedHostsFuture));

            // Quem estourou o teto de 120s continuaria "rodando" no feed para sempre:
            // quem marca OK é a própria tarefa, e a que não terminou não marca nada.
            progresso.sincroniza(moduleStatus);

            List<String>                  sensitiveRobotsPaths     = robotsFuture.getNow(List.of());
            List<HttpMethodFinding>       dangerousHttpMethods     = methodsFuture.getNow(List.of());
            List<DirectoryListingFinding> directoryListingFindings = dirListFuture.getNow(List.of());
            DnsSecurityResult             dnsSecurityResult        = dnsFuture.getNow(null);
            TechFingerprintResult             techFingerprint      = fingerprintFuture.getNow(null);
            List<SubdomainTakeoverFinding>    takeoverFindings     = takeoverFuture.getNow(List.of());
            CertTransparencyResult               certTransparency     = certTransFuture.getNow(null);
            List<HostHeaderFinding>    hostHeaderFindings   = hostHeaderFuture.getNow(List.of());
            List<SourceMapFinding>     sourceMapFindings    = sourceMapFuture.getNow(List.of());
            List<ApiDocsExposureFinding>         apiDocsExposure      = apiDocsFuture.getNow(List.of());
            List<GraphQlIntrospectionFinding>    graphQlIntrospection = graphQlFuture.getNow(List.of());
            List<CVEFinding>              cveFindings              = cveFuture.getNow(List.of());
            List<RelatedHostHeaders>      relatedHostHeaders       = relatedHostsFuture.getNow(List.of());

            SecurityTxtService.SecurityTxtResult securityTxt = secTxtFuture.getNow(null);
            boolean secTxtFound   = securityTxt != null && securityTxt.found();
            String  secTxtContact = securityTxt != null ? securityTxt.contact() : null;

            ScoreResult passiveScore = scoreService.calculate(
                    sslInfo, tlsDetails, analyzedHeaders, redirectsToHttps,
                    false, inputSurfaceDetected, false, false, false, List.of(),
                    null, cookieIssues, sensitiveRobotsPaths, serverVersionExposed,
                    List.of(), dangerousHttpMethods, secTxtFound,
                    List.of(), directoryListingFindings, dnsSecurityResult, null,
                    cveFindings, apiDocsExposure, graphQlIntrospection, jwtSecurity,
                    List.of(), List.of(), hostHeaderFindings, sourceMapFindings, List.of()
            );

            scoreService.appendPartialNote(passiveScore, naoConcluidas(moduleStatus));

            // ── Monta resultado passivo ────────────────────────────────────────
            ScanResult passiveResult = ScanResult.builder()
                    .lang(idiomaDaRequisicao())
                    .degradedModules(modulosDegradados(moduleStatus))
                    .url(inputUrl).finalUrl(fetch.getFinalUrl())
                    .analyzedHost(analyzedHost)
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
                    .certTransparency(certTransparency)
                    .apiDocsExposure(apiDocsExposure)
                    .graphQlIntrospection(graphQlIntrospection)
                    .jwtSecurity(jwtSecurity)
                    .pathTraversal(List.of())
                    .ssrfFindings(List.of())
                    .hostHeaderFindings(hostHeaderFindings)
                    .sourceMapFindings(sourceMapFindings)
                    .crlfFindings(List.of())
                    .changes(scanChangeDetector.detect(
                            buildPartialForDiff(passiveScore, sslInfo, analyzedHeaders,
                                    serverVersionExposed, dangerousHttpMethods, List.of(),
                                    dnsSecurityResult, null, techFingerprint, List.of()),
                            previousScan))                             // ← change detection
                    .moduleStatus(moduleStatus)
                    .relatedHostHeaders(relatedHostHeaders)
                    .score(passiveScore)
                    .build();

            // Compliance gerado após montagem do passiveResult (necessita do objeto completo)
            passiveResult.setCompliance(complianceMappingService.generate(passiveResult));

            // ── Fase 3: ownership check ────────────────────────────────────────
            // Posse é exigida SEMPRE. Antes havia uma heurística
            // (requiresOwnershipForActiveScan) que dispensava a checagem quando o
            // alvo "parecia bem configurado" — invertida: liberava justamente os
            // scans ativos contra sites de terceiros bem mantidos. Quão hardened o
            // alvo é não diz nada sobre ter autorização para atacá-lo.
            if (active) {
                // Só equipe da plataforma dispensa a prova de posse. Antes era
                // `role == OWNER || role == ADMIN` — e /auth/register entrega OWNER
                // a quem se cadastrar, o que tornava a checagem opcional para todos.
                boolean bypassOwnership = platformStaffService.isStaff(currentUser);
                if (!bypassOwnership &&
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
                Account account = currentUser != null ? currentUser.getAccount() : null;
                scanHistoryService.save(passiveResult, account, origin);
                if (currentUser != null) {
                    auditService.log(currentUser, AuditAction.SCAN_COMPLETED,
                            "passive — " + inputUrl + " — score=" + passiveResult.getScore().getScore());
                    degradationNotificationService.checkAndNotify(passiveResult, account);
                }
                return passiveResult;
            }

            // ── Fase 4: checks ativos — PARALELOS ─────────────────────────────
            ExecutorService activePool = Executors.newFixedThreadPool(6);

            var corsFuture     = CompletableFuture.supplyAsync(
                    progresso.acompanha(ScanCheck.CORS,
                            () -> corsAnalyzerService.analyze(target)), activePool).exceptionally(e -> null);
            var filesFuture    = CompletableFuture.supplyAsync(
                    progresso.acompanha(ScanCheck.SENSITIVE_FILES,
                            () -> sensitiveFileService.scan(target)), activePool).exceptionally(e -> List.of());
            var wafFuture      = CompletableFuture.supplyAsync(
                    progresso.acompanha(ScanCheck.WAF,
                            () -> wafDetectionService.scan(target)), activePool).exceptionally(e -> null);
            var redirectFuture = CompletableFuture.supplyAsync(
                    progresso.acompanha(ScanCheck.OPEN_REDIRECT,
                            () -> openRedirectService.scan(target, true)), activePool).exceptionally(e -> List.of());
            var xssFuture = inputSurfaceDetected
                    ? CompletableFuture.supplyAsync(progresso.acompanha(ScanCheck.REFLECTED_XSS,
                            () -> xssProbeService.reflectedMarkerAppears(target)), activePool).exceptionally(e -> false)
                    : CompletableFuture.completedFuture(false);
            var dbFuture = inputSurfaceDetected
                    ? CompletableFuture.supplyAsync(progresso.acompanha(ScanCheck.DB_ERROR,
                            () -> errorDisclosureService.detectsDbErrorLeakage(target)), activePool).exceptionally(e -> false)
                    : CompletableFuture.completedFuture(false);
            var pathTraversalFuture = inputSurfaceDetected
                    ? CompletableFuture.supplyAsync(
                            progresso.acompanha(ScanCheck.PATH_TRAVERSAL,
                                    () -> pathTraversalService.scan(target)), activePool).exceptionally(e -> List.of())
                    : CompletableFuture.completedFuture(List.<PathTraversalFinding>of());
            // CRLF roda SEMPRE em modo ativo — inclui path injection que não depende de parâmetros
            var crlfFuture = CompletableFuture.supplyAsync(
                    progresso.acompanha(ScanCheck.CRLF,
                            () -> crlfService.scan(target)), activePool).exceptionally(e -> List.of());
            var ssrfFuture = inputSurfaceDetected
                    ? CompletableFuture.supplyAsync(
                            progresso.acompanha(ScanCheck.SSRF,
                                    () -> ssrfService.scan(target)), activePool).exceptionally(e -> List.of())
                    : CompletableFuture.completedFuture(List.<SsrfFinding>of());
            var portFuture = (host != null && !host.isBlank())
                    ? CompletableFuture.supplyAsync(progresso.acompanha(ScanCheck.PORT_SCAN,
                            () -> portScanService.scanCommonPorts(host)), activePool).exceptionally(e -> List.of())
                    : CompletableFuture.completedFuture(List.<PortFinding>of());

            try {
                CompletableFuture.allOf(
                        corsFuture, filesFuture, wafFuture, redirectFuture,
                        xssFuture, dbFuture, portFuture, pathTraversalFuture, ssrfFuture, crlfFuture
                ).get(120, TimeUnit.SECONDS);
            } catch (Exception ignored) {}

            activePool.shutdownNow();

            // ── Status dos módulos ativos ─────────────────────────────────────
            // Probes dependentes de superfície de input (query params): SKIPPED quando ausentes.
            moduleStatus.put(ScanCheck.CORS.name(),            moduleState(corsFuture));
            moduleStatus.put(ScanCheck.SENSITIVE_FILES.name(), moduleState(filesFuture));
            moduleStatus.put(ScanCheck.WAF.name(),             moduleState(wafFuture));
            moduleStatus.put(ScanCheck.OPEN_REDIRECT.name(),   moduleState(redirectFuture));
            moduleStatus.put(ScanCheck.CRLF.name(),            moduleState(crlfFuture));
            moduleStatus.put(ScanCheck.PORT_SCAN.name(),
                    (host != null && !host.isBlank()) ? moduleState(portFuture) : "SKIPPED");
            moduleStatus.put(ScanCheck.REFLECTED_XSS.name(),
                    inputSurfaceDetected ? moduleState(xssFuture) : "SKIPPED");
            moduleStatus.put(ScanCheck.DB_ERROR.name(),
                    inputSurfaceDetected ? moduleState(dbFuture) : "SKIPPED");
            moduleStatus.put(ScanCheck.PATH_TRAVERSAL.name(),
                    inputSurfaceDetected ? moduleState(pathTraversalFuture) : "SKIPPED");
            moduleStatus.put(ScanCheck.SSRF.name(),
                    inputSurfaceDetected ? moduleState(ssrfFuture) : "SKIPPED");

            // Além do timeout, esta passada é o que transforma em PULADO os probes que
            // não tinham onde rodar — sem superfície de input, sem host para as portas.
            progresso.sincroniza(moduleStatus);

            CorsResult                 corsResult            = corsFuture.getNow(null);
            List<SensitiveFileFinding> sensitiveFiles        = filesFuture.getNow(List.of());
            WafDetectionResult         wafDetectionResult    = wafFuture.getNow(null);
            List<OpenRedirectFinding>  openRedirectFindings  = redirectFuture.getNow(List.of());
            boolean xssProbePerformed     = inputSurfaceDetected;
            boolean reflectedXssSuspected = xssFuture.getNow(false);
            boolean dbErrorLeakage        = dbFuture.getNow(false);
            List<PortFinding> openPorts           = portFuture.getNow(List.of());
            List<PathTraversalFinding> pathTraversal = pathTraversalFuture.getNow(List.of());
            List<SsrfFinding> ssrfFindings = ssrfFuture.getNow(List.of());
            List<CrlfFinding> crlfFindings = crlfFuture.getNow(List.of());

            ScoreResult score = scoreService.calculate(
                    sslInfo, tlsDetails, analyzedHeaders, redirectsToHttps,
                    true, inputSurfaceDetected, dbErrorLeakage,
                    xssProbePerformed, reflectedXssSuspected, openPorts,
                    corsResult, cookieIssues, sensitiveRobotsPaths, serverVersionExposed,
                    sensitiveFiles, dangerousHttpMethods, secTxtFound,
                    openRedirectFindings, directoryListingFindings,
                    dnsSecurityResult, wafDetectionResult, cveFindings,
                    apiDocsExposure, graphQlIntrospection, jwtSecurity,
                    pathTraversal, ssrfFindings, hostHeaderFindings, sourceMapFindings, crlfFindings
            );

            scoreService.appendPartialNote(score, naoConcluidas(moduleStatus));

            ScanResult result = ScanResult.builder()
                    .lang(idiomaDaRequisicao())
                    .degradedModules(modulosDegradados(moduleStatus))
                    .url(inputUrl).finalUrl(fetch.getFinalUrl())
                    .analyzedHost(analyzedHost)
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
                    .apiDocsExposure(apiDocsExposure)
                    .graphQlIntrospection(graphQlIntrospection)
                    .jwtSecurity(jwtSecurity)
                    .pathTraversal(pathTraversal)
                    .ssrfFindings(ssrfFindings)
                    .hostHeaderFindings(hostHeaderFindings)
                    .sourceMapFindings(sourceMapFindings)
                    .crlfFindings(crlfFindings)
                    .changes(scanChangeDetector.detect(              // ← change detection
                            buildPartialForDiff(score, sslInfo, analyzedHeaders,
                                    serverVersionExposed, dangerousHttpMethods, openPorts,
                                    dnsSecurityResult, wafDetectionResult, techFingerprint, sensitiveFiles),
                            previousScan))
                    .moduleStatus(moduleStatus)
                    .relatedHostHeaders(relatedHostHeaders)
                    .score(score)
                    .build();

            result.setCompliance(complianceMappingService.generate(result));

            scanCacheService.put(cacheKey, result);
            Account account = currentUser != null ? currentUser.getAccount() : null;
            scanHistoryService.save(result, account, origin);
            if (currentUser != null) {
                auditService.log(currentUser, AuditAction.SCAN_COMPLETED,
                        "active — " + inputUrl + " — score=" + result.getScore().getScore());
                degradationNotificationService.checkAndNotify(result, account);
            }
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

    /**
     * Estado de um módulo: completou dentro do orçamento da fase (sucesso ou fallback
     * via exceptionally) = "OK"; não completou a tempo = "TIMEOUT" (não verificado —
     * não tratar como "seguro"). SKIPPED é atribuído à parte para probes condicionais.
     */
    private static String moduleState(CompletableFuture<?> f) {
        return f.isDone() ? "OK" : "TIMEOUT";
    }

    /**
     * Verificações que não concluíram — timeout ou erro.
     *
     * SKIPPED fica de fora: é decisão do scan (probe de injeção sem parâmetro para
     * injetar, port scan sem host), não falha de coleta. Avisar sobre o que foi
     * deliberadamente pulado transformaria a nota em ruído e ensinaria o cliente a
     * ignorá-la.
     */
    private static List<ScanCheck> naoConcluidas(Map<String, String> moduleStatus) {
        return moduleStatus.entrySet().stream()
                .filter(e -> "TIMEOUT".equals(e.getValue()) || "ERROR".equals(e.getValue()))
                .map(e -> {
                    try { return ScanCheck.valueOf(e.getKey()); }
                    catch (IllegalArgumentException ex) { return null; }
                })
                .filter(Objects::nonNull)
                .toList();
    }

    /**
     * Módulos da barra lateral com alguma verificação não concluída.
     *
     * Sem isto a barra lateral marcava ✓ verde num módulo cuja verificação nunca
     * rodou — afirmando "seguro" sobre o que o scan não chegou a apurar, que é o
     * pior tipo de erro num produto de auditoria.
     */
    private static List<String> modulosDegradados(Map<String, String> moduleStatus) {
        return naoConcluidas(moduleStatus).stream()
                .map(ScanCheck::moduloUi)
                .distinct()
                .toList();
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
    private static final String CACHE_VERSION = "v3";

    /**
     * O idioma entra na chave porque o resultado guardado já tem o TEXTO montado:
     * sem isso, um scan feito em português seria devolvido a quem pediu inglês,
     * pelos 2 minutos de TTL.
     *
     * Custa refazer o scan uma vez por idioma no mesmo host dentro da janela. O
     * conserto sem esse custo é o resultado guardar ID + parâmetros e o texto ser
     * montado na saída — mudança de contrato, grande, e que esta etapa não faz.
     *
     * Usa só o idioma, não o locale inteiro: en-US e en-GB leem o mesmo catálogo e
     * não têm motivo para ocupar entradas separadas.
     */
    /**
     * Idioma em que os textos deste scan estão sendo montados.
     *
     * Mesma fonte da chave de cache, de propósito: se as duas divergissem, o
     * resultado servido de cache viria carimbado com um idioma que não é o dele.
     * Vale nos três caminhos — o síncrono roda na thread da requisição, o assíncrono
     * propaga o locale, e o agendado o define a partir do que ficou guardado no
     * agendamento ({@code ScheduledScanService.idiomaDe}).
     */
    private String idiomaDaRequisicao() {
        return LocaleContextHolder.getLocale().getLanguage();
    }

    private String buildCacheKey(String url, boolean active) {
        String h = extractHostSafe(url);
        return CACHE_VERSION + ":scan:" + (h != null ? h : url) + ":active=" + active
                + ":lang=" + LocaleContextHolder.getLocale().getLanguage();
    }
}