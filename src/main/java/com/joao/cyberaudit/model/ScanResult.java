package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;
import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ScanResult {

    private String url;
    private String finalUrl;
    private int httpStatus;

    private boolean redirectsToHttps;
    private SSLInfo sslInfo;
    private TlsDetails tlsDetails;

    private Map<String, String> headers;
    private boolean serverVersionExposed;

    private boolean activeMode;
    private boolean inputSurfaceDetected;
    private boolean dbErrorLeakageSuspected;
    private boolean xssProbePerformed;
    private boolean reflectedXssSuspected;
    private List<PortFinding> openPorts;

    private CorsResult corsResult;
    private List<CookieFinding> cookieIssues;
    private List<String> sensitiveRobotsPaths;

    private ScoreResult score;

}
