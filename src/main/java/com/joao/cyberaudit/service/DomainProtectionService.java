package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.ScanResult;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.UUID;

@Service
public class DomainProtectionService {

    private static final String OWNERSHIP_TOKEN_PREFIX = "cyberaudit-verify=";

    private final HttpClient client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    public boolean requiresOwnershipForActiveScan(ScanResult passiveScan) {
        if (passiveScan == null) return true;

        if (passiveScan.isInputSurfaceDetected()) return true;

        if (passiveScan.getScore() != null &&
                passiveScan.getScore().getScore() < 60) return true;

        if (passiveScan.getOpenPorts() != null) {
            boolean sensitivePorts = passiveScan.getOpenPorts().stream()
                    .anyMatch(p -> p.getPort() != 80 && p.getPort() != 443
                            && "OPEN".equals(p.getState()));
            if (sensitivePorts) return true;
        }

        // HSTS e CSP ausentes = provavelmente app em produção sem hardening
        if (passiveScan.getHeaders() != null) {
            String hsts = passiveScan.getHeaders().get("Strict-Transport-Security");
            String csp  = passiveScan.getHeaders().get("Content-Security-Policy");
            boolean hstsMissing = hsts != null && hsts.startsWith("MISSING");
            boolean cspMissing  = csp  != null && csp.startsWith("MISSING");
            if (hstsMissing && cspMissing) return true;
        }

        return false;
    }

    public boolean isOwnershipVerified(String host) {
        try {
            String url = "https://" + host + "/.well-known/cyberaudit.txt";

            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .GET()
                    .timeout(Duration.ofSeconds(5))
                    .header("User-Agent", "CyberAuditVerifier/1.0")
                    .build();

            HttpResponse<String> resp = client.send(
                    req, HttpResponse.BodyHandlers.ofString());

            if (resp.statusCode() != 200) return false;

            String body = resp.body() == null ? "" : resp.body().trim();
            return body.startsWith(OWNERSHIP_TOKEN_PREFIX)
                    && body.length() > OWNERSHIP_TOKEN_PREFIX.length();

        } catch (Exception e) {
            return false;
        }
    }

    public String generateVerificationToken(String host) {
        String token = UUID.nameUUIDFromBytes(
                ("cyberaudit:" + host.toLowerCase()).getBytes()
        ).toString();
        return OWNERSHIP_TOKEN_PREFIX + token;
    }
}