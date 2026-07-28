package com.joao.cyberaudit.model;

import com.joao.cyberaudit.dto.ComplianceReport;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;
import java.util.Map;

@Getter @Setter @Builder(toBuilder = true) @AllArgsConstructor @NoArgsConstructor
public class ScanResult {

    private String url;
    private String finalUrl;
    private int    httpStatus;

    /**
     * Host cujos headers de resposta foram efetivamente analisados (após redirects).
     * Explicita "de qual host são estes headers" — evita confundir com headers de
     * subdomínios de API (ex: server.exemplo.com) que o usuário pode ver no DevTools.
     */
    private String analyzedHost;

    private boolean    redirectsToHttps;
    private SSLInfo    sslInfo;
    private TlsDetails tlsDetails;

    private Map<String, String> headers;
    private boolean             serverVersionExposed;

    private boolean           activeMode;
    private boolean           inputSurfaceDetected;
    private boolean           dbErrorLeakageSuspected;
    private boolean           xssProbePerformed;
    private boolean           reflectedXssSuspected;
    private List<PortFinding> openPorts;
    private WafDetectionResult wafDetectionResult;

    private CorsResult          corsResult;
    private List<CookieFinding> cookieIssues;
    private List<String>        sensitiveRobotsPaths;

    private List<SensitiveFileFinding>    sensitiveFiles;
    private List<HttpMethodFinding>       dangerousHttpMethods;
    private boolean                       securityTxtPresent;
    private String                        securityTxtContact;
    private DnsSecurityResult             dnsSecurityResult;
    private List<OpenRedirectFinding>     openRedirectFindings;
    private List<DirectoryListingFinding> directoryListingFindings;

    private TechFingerprintResult             techFingerprint;
    private List<CVEFinding>                  cveFindings;
    private List<ScanChange>                  changes;
    private List<SubdomainTakeoverFinding>    subdomainTakeover;
    private CertTransparencyResult            certTransparency;
    private List<ApiDocsExposureFinding>      apiDocsExposure;
    private List<GraphQlIntrospectionFinding> graphQlIntrospection;
    private List<JwtSecurityFinding>          jwtSecurity;
    private List<PathTraversalFinding>        pathTraversal;
    private List<SsrfFinding>                ssrfFindings;
    private List<HostHeaderFinding>           hostHeaderFindings;
    private List<SourceMapFinding>            sourceMapFindings;
    private List<CrlfFinding>                crlfFindings;

    private ScoreResult score;

    /**
     * Status de execução por módulo: nome → "OK" | "TIMEOUT" | "SKIPPED".
     * Distingue "verificado e sem achado" de "não conseguiu verificar".
     */
    private Map<String, String> moduleStatus;

    /**
     * Headers de segurança de hosts relacionados (api., server., www. ...) — informativo,
     * não entra no score. Esclarece que outros hosts do site podem ter config diferente.
     */
    private List<RelatedHostHeaders> relatedHostHeaders;

    /** Mapeamento de conformidade LGPD / ISO 27001:2022 — computado pelo orchestrator */
    private ComplianceReport compliance;

    /**
     * true quando o requester (guest ou plano FREE) NÃO tem acesso ao detalhe:
     * as issues vêm sem impacto/correção e o breakdown fica travado no front.
     * Aplicado por {@code ScanEntitlementService} — nunca muta o resultado em cache.
     */
    private boolean detailsLocked;
}
