package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ScanResult {

    private String url;
    private String finalUrl;
    private int    httpStatus;

    private boolean         redirectsToHttps;
    private SSLInfo         sslInfo;
    private TlsDetails      tlsDetails;

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

    private TechFingerprintResult techFingerprint;
    private List<CVEFinding>      cveFindings;
    private List<ScanChange>               changes;
    private List<SubdomainTakeoverFinding> subdomainTakeover;
    private CertTransparencyResult          certTransparency;
    private List<ApiDocsExposureFinding>    apiDocsExposure;
    private List<GraphQlIntrospectionFinding> graphQlIntrospection;

    private ScoreResult score;
}
