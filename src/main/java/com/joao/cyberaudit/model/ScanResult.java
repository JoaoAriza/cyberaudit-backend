package com.joao.cyberaudit.model;

import lombok.Builder;
import lombok.Data;

import java.util.Map;
import java.util.List;

@Data
@Builder
public class ScanResult {

    private String url;
    private String finalUrl;
    private int httpStatus;

    private boolean redirectsToHttps;
    private SSLInfo sslInfo;
    private TlsDetails tlsDetails;          // NOVO

    private Map<String, String> headers;
    private boolean serverVersionExposed;   // NOVO

    private boolean activeMode;
    private boolean inputSurfaceDetected;
    private boolean dbErrorLeakageSuspected;
    private boolean xssProbePerformed;
    private boolean reflectedXssSuspected;
    private List<PortFinding> openPorts;

    private CorsResult corsResult;          // NOVO

    private List<CookieFinding> cookieIssues; // NOVO

    private List<String> sensitiveRobotsPaths; // NOVO

    private ScoreResult score;

}
