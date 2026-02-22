package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import java.util.Map;
import java.util.List;

@Data
@AllArgsConstructor
public class ScanResult {

    private String url;
    private String finalUrl;
    private int httpStatus;
    private boolean redirectsToHttps;

    private boolean activeMode;
    private boolean inputSurfaceDetected;
    private boolean dbErrorLeakageSuspected;

    private boolean xssProbePerformed;
    private boolean reflectedXssSuspected;

    private SSLInfo sslInfo;
    private Map<String, String> headers;
    private ScoreResult score;

    private List<PortFinding> openPorts;
}
