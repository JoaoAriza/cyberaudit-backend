package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.*;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Compara dois ScanResult (atual vs anterior) e retorna a lista de mudanças.
 * Detecta melhorias, regressões e alterações neutras que um analista
 * precisaria saber entre dois scans do mesmo alvo.
 */
@Service
public class ScanChangeDetector {

    public List<ScanChange> detect(ScanResult current, ScanResult previous) {
        if (previous == null) return List.of();

        List<ScanChange> changes = new ArrayList<>();

        detectScore(current, previous, changes);
        detectSsl(current, previous, changes);
        detectHeaders(current, previous, changes);
        detectWaf(current, previous, changes);
        detectDns(current, previous, changes);
        detectHttpMethods(current, previous, changes);
        detectPorts(current, previous, changes);
        detectSensitiveFiles(current, previous, changes);
        detectServerVersion(current, previous, changes);
        detectTech(current, previous, changes);

        // Ordena por severidade
        changes.sort(Comparator.comparingInt(c -> severityOrder(c.getSeverity())));
        return changes;
    }

    // ── Score ─────────────────────────────────────────────────────────────────

    private void detectScore(ScanResult cur, ScanResult prev, List<ScanChange> out) {
        int curScore  = cur.getScore()  != null ? cur.getScore().getScore()  : 0;
        int prevScore = prev.getScore() != null ? prev.getScore().getScore() : 0;
        int delta     = curScore - prevScore;

        if (Math.abs(delta) < 5) return; // mudança pequena, ignora

        String changeType = delta > 0 ? "IMPROVED" : "DEGRADED";
        String severity   = Math.abs(delta) >= 20 ? "HIGH"
                : Math.abs(delta) >= 10 ? "MEDIUM" : "LOW";

        out.add(ScanChange.builder()
                .category("SCORE")
                .field("score")
                .changeType(changeType)
                .oldValue(prevScore + "/100")
                .newValue(curScore + "/100")
                .severity(severity)
                .description(String.format("Score %s de %d → %d (%+d pontos)",
                        delta > 0 ? "subiu" : "caiu", prevScore, curScore, delta))
                .build());
    }

    // ── SSL ───────────────────────────────────────────────────────────────────

    private void detectSsl(ScanResult cur, ScanResult prev, List<ScanChange> out) {
        SSLInfo curSsl  = cur.getSslInfo();
        SSLInfo prevSsl = prev.getSslInfo();
        if (curSsl == null || prevSsl == null) return;

        // Validade mudou
        if (curSsl.isValid() != prevSsl.isValid()) {
            boolean degraded = !curSsl.isValid() && prevSsl.isValid();
            out.add(ScanChange.builder()
                    .category("SSL")
                    .field("certificate validity")
                    .changeType(degraded ? "DEGRADED" : "IMPROVED")
                    .oldValue(prevSsl.isValid() ? "válido" : "inválido")
                    .newValue(curSsl.isValid()  ? "válido" : "inválido")
                    .severity(degraded ? "HIGH" : "MEDIUM")
                    .description(degraded
                            ? "Certificado SSL tornou-se inválido"
                            : "Certificado SSL voltou a ser válido")
                    .build());
        }

        // Data de expiração mudou (novo certificado emitido)
        String curExp  = curSsl.getExpirationDate();
        String prevExp = prevSsl.getExpirationDate();
        if (curExp != null && !curExp.equals(prevExp) && prevExp != null) {
            out.add(ScanChange.builder()
                    .category("SSL")
                    .field("expiration date")
                    .changeType("CHANGED")
                    .oldValue(prevExp)
                    .newValue(curExp)
                    .severity("INFO")
                    .description("Novo certificado SSL emitido — data de expiração alterada")
                    .build());
        }

        // Cruzou thresholds críticos de expiração
        long curDays  = curSsl.getDaysRemaining();
        long prevDays = prevSsl.getDaysRemaining();
        if (prevDays > 30 && curDays <= 30 && curDays > 0) {
            out.add(ScanChange.builder()
                    .category("SSL")
                    .field("days remaining")
                    .changeType("DEGRADED")
                    .oldValue(prevDays + " dias")
                    .newValue(curDays + " dias")
                    .severity("HIGH")
                    .description("Certificado SSL entra na janela crítica de 30 dias")
                    .build());
        } else if (prevDays > 90 && curDays <= 90 && curDays > 30) {
            out.add(ScanChange.builder()
                    .category("SSL")
                    .field("days remaining")
                    .changeType("DEGRADED")
                    .oldValue(prevDays + " dias")
                    .newValue(curDays + " dias")
                    .severity("MEDIUM")
                    .description("Certificado SSL entra na janela de atenção de 90 dias")
                    .build());
        }
    }

    // ── Security Headers ──────────────────────────────────────────────────────

    private void detectHeaders(ScanResult cur, ScanResult prev, List<ScanChange> out) {
        Map<String, String> curH  = cur.getHeaders()  != null ? cur.getHeaders()  : Map.of();
        Map<String, String> prevH = prev.getHeaders() != null ? prev.getHeaders() : Map.of();

        Set<String> allKeys = new HashSet<>();
        allKeys.addAll(curH.keySet());
        allKeys.addAll(prevH.keySet());

        for (String header : allKeys) {
            if ("error".equals(header)) continue;

            String curVal  = curH.get(header);
            String prevVal = prevH.get(header);

            if (Objects.equals(curVal, prevVal)) continue;

            boolean wasOk    = prevVal != null && prevVal.startsWith("OK");
            boolean nowOk    = curVal  != null && curVal.startsWith("OK");
            boolean wasMiss  = prevVal == null || prevVal.startsWith("MISSING");
            boolean nowMiss  = curVal  == null || curVal.startsWith("MISSING");

            String changeType;
            String severity;
            String description;

            if (wasMiss && nowOk) {
                changeType  = "IMPROVED";
                severity    = "MEDIUM";
                description = header + " adicionado";
            } else if (wasOk && nowMiss) {
                changeType  = "DEGRADED";
                severity    = criticalHeader(header) ? "HIGH" : "MEDIUM";
                description = header + " removido";
            } else if (!Objects.equals(curVal, prevVal)) {
                changeType  = "CHANGED";
                severity    = "LOW";
                description = header + " alterado";
            } else {
                continue;
            }

            out.add(ScanChange.builder()
                    .category("HEADERS")
                    .field(header)
                    .changeType(changeType)
                    .oldValue(prevVal != null ? prevVal : "—")
                    .newValue(curVal  != null ? curVal  : "—")
                    .severity(severity)
                    .description(description)
                    .build());
        }
    }

    // ── WAF ───────────────────────────────────────────────────────────────────

    private void detectWaf(ScanResult cur, ScanResult prev, List<ScanChange> out) {
        boolean curWaf  = cur.getWafDetectionResult()  != null && cur.getWafDetectionResult().isDetected();
        boolean prevWaf = prev.getWafDetectionResult() != null && prev.getWafDetectionResult().isDetected();

        if (curWaf == prevWaf) return;

        out.add(ScanChange.builder()
                .category("WAF")
                .field("WAF detection")
                .changeType(curWaf ? "IMPROVED" : "DEGRADED")
                .oldValue(prevWaf ? "detectado" : "não detectado")
                .newValue(curWaf  ? "detectado" : "não detectado")
                .severity(curWaf ? "LOW" : "MEDIUM")
                .description(curWaf
                        ? "WAF/CDN passou a ser detectado: " + cur.getWafDetectionResult().getProvider()
                        : "WAF/CDN não mais detectado")
                .build());
    }

    // ── DNS ───────────────────────────────────────────────────────────────────

    private void detectDns(ScanResult cur, ScanResult prev, List<ScanChange> out) {
        DnsSecurityResult curDns  = cur.getDnsSecurityResult();
        DnsSecurityResult prevDns = prev.getDnsSecurityResult();
        if (curDns == null || prevDns == null) return;

        // SPF
        if (!Objects.equals(curDns.getSpfPolicy(), prevDns.getSpfPolicy())) {
            out.add(ScanChange.builder()
                    .category("DNS")
                    .field("SPF policy")
                    .changeType("CHANGED")
                    .oldValue(prevDns.getSpfPolicy())
                    .newValue(curDns.getSpfPolicy())
                    .severity("MEDIUM")
                    .description("Política SPF alterada")
                    .build());
        }

        // DMARC
        if (!Objects.equals(curDns.getDmarcPolicy(), prevDns.getDmarcPolicy())) {
            boolean improved = isStrongerDmarc(curDns.getDmarcPolicy(), prevDns.getDmarcPolicy());
            out.add(ScanChange.builder()
                    .category("DNS")
                    .field("DMARC policy")
                    .changeType(improved ? "IMPROVED" : "DEGRADED")
                    .oldValue("p=" + prevDns.getDmarcPolicy())
                    .newValue("p=" + curDns.getDmarcPolicy())
                    .severity("MEDIUM")
                    .description("Política DMARC alterada: p=" + prevDns.getDmarcPolicy()
                            + " → p=" + curDns.getDmarcPolicy())
                    .build());
        }

        // Email spoofing risk
        if (!Objects.equals(curDns.getEmailSpoofingRisk(), prevDns.getEmailSpoofingRisk())) {
            int curRisk  = riskLevel(curDns.getEmailSpoofingRisk());
            int prevRisk = riskLevel(prevDns.getEmailSpoofingRisk());
            out.add(ScanChange.builder()
                    .category("DNS")
                    .field("email spoofing risk")
                    .changeType(curRisk < prevRisk ? "IMPROVED" : "DEGRADED")
                    .oldValue(prevDns.getEmailSpoofingRisk())
                    .newValue(curDns.getEmailSpoofingRisk())
                    .severity("MEDIUM")
                    .description("Risco de email spoofing: "
                            + prevDns.getEmailSpoofingRisk() + " → " + curDns.getEmailSpoofingRisk())
                    .build());
        }
    }

    // ── HTTP Methods ──────────────────────────────────────────────────────────

    private void detectHttpMethods(ScanResult cur, ScanResult prev, List<ScanChange> out) {
        Set<String> curMethods  = methodSet(cur.getDangerousHttpMethods());
        Set<String> prevMethods = methodSet(prev.getDangerousHttpMethods());

        // Novos métodos perigosos
        for (String m : setDiff(curMethods, prevMethods)) {
            out.add(ScanChange.builder()
                    .category("HTTP METHODS")
                    .field(m)
                    .changeType("DEGRADED")
                    .oldValue("não detectado")
                    .newValue("habilitado")
                    .severity("HIGH")
                    .description("Novo método HTTP perigoso detectado: " + m)
                    .build());
        }

        // Métodos que sumiram
        for (String m : setDiff(prevMethods, curMethods)) {
            out.add(ScanChange.builder()
                    .category("HTTP METHODS")
                    .field(m)
                    .changeType("IMPROVED")
                    .oldValue("habilitado")
                    .newValue("não detectado")
                    .severity("LOW")
                    .description("Método HTTP perigoso removido: " + m)
                    .build());
        }
    }

    // ── Ports ─────────────────────────────────────────────────────────────────

    private void detectPorts(ScanResult cur, ScanResult prev, List<ScanChange> out) {
        Set<Integer> curPorts  = portSet(cur.getOpenPorts());
        Set<Integer> prevPorts = portSet(prev.getOpenPorts());

        for (int port : setDiff(curPorts, prevPorts)) {
            out.add(ScanChange.builder()
                    .category("PORTS")
                    .field("port " + port)
                    .changeType("DEGRADED")
                    .oldValue("fechada")
                    .newValue("aberta")
                    .severity("HIGH")
                    .description("Nova porta aberta detectada: " + port)
                    .build());
        }

        for (int port : setDiff(prevPorts, curPorts)) {
            out.add(ScanChange.builder()
                    .category("PORTS")
                    .field("port " + port)
                    .changeType("IMPROVED")
                    .oldValue("aberta")
                    .newValue("fechada")
                    .severity("LOW")
                    .description("Porta fechada: " + port)
                    .build());
        }
    }

    // ── Sensitive Files ───────────────────────────────────────────────────────

    private void detectSensitiveFiles(ScanResult cur, ScanResult prev, List<ScanChange> out) {
        Set<String> curFiles  = fileSet(cur.getSensitiveFiles());
        Set<String> prevFiles = fileSet(prev.getSensitiveFiles());

        for (String f : setDiff(curFiles, prevFiles)) {
            out.add(ScanChange.builder()
                    .category("FILES")
                    .field(f)
                    .changeType("DEGRADED")
                    .oldValue("não exposto")
                    .newValue("exposto")
                    .severity("HIGH")
                    .description("Novo arquivo sensível exposto: " + f)
                    .build());
        }

        for (String f : setDiff(prevFiles, curFiles)) {
            out.add(ScanChange.builder()
                    .category("FILES")
                    .field(f)
                    .changeType("IMPROVED")
                    .oldValue("exposto")
                    .newValue("não detectado")
                    .severity("LOW")
                    .description("Arquivo sensível não mais acessível: " + f)
                    .build());
        }
    }

    // ── Server Version ────────────────────────────────────────────────────────

    private void detectServerVersion(ScanResult cur, ScanResult prev, List<ScanChange> out) {
        if (cur.isServerVersionExposed() == prev.isServerVersionExposed()) return;
        out.add(ScanChange.builder()
                .category("HEADERS")
                .field("server version disclosure")
                .changeType(cur.isServerVersionExposed() ? "DEGRADED" : "IMPROVED")
                .oldValue(prev.isServerVersionExposed() ? "exposto" : "oculto")
                .newValue(cur.isServerVersionExposed()  ? "exposto" : "oculto")
                .severity(cur.isServerVersionExposed() ? "MEDIUM" : "LOW")
                .description(cur.isServerVersionExposed()
                        ? "Versão do servidor passou a ser exposta"
                        : "Versão do servidor foi ocultada")
                .build());
    }

    // ── Tech Stack ────────────────────────────────────────────────────────────

    private void detectTech(ScanResult cur, ScanResult prev, List<ScanChange> out) {
        TechFingerprintResult curTf  = cur.getTechFingerprint();
        TechFingerprintResult prevTf = prev.getTechFingerprint();
        if (curTf == null || prevTf == null) return;

        checkTechField("CMS",        curTf.getCms(),       prevTf.getCms(),       out);
        checkTechField("Framework",  curTf.getFramework(), prevTf.getFramework(), out);
        checkTechField("Web Server", curTf.getWebServer(), prevTf.getWebServer(), out);
        checkTechField("Backend",    curTf.getBackend(),   prevTf.getBackend(),   out);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void checkTechField(String label, String curVal, String prevVal, List<ScanChange> out) {
        if (Objects.equals(curVal, prevVal)) return;
        if (curVal == null) return; // desapareceu — pode ser detecção instável, ignora
        out.add(ScanChange.builder()
                .category("TECH")
                .field(label)
                .changeType("CHANGED")
                .oldValue(prevVal != null ? prevVal : "não detectado")
                .newValue(curVal)
                .severity("INFO")
                .description(label + " alterado: "
                        + (prevVal != null ? prevVal : "não detectado") + " → " + curVal)
                .build());
    }

    private boolean criticalHeader(String header) {
        return header.contains("Strict-Transport") || header.contains("Content-Security");
    }

    private boolean isStrongerDmarc(String cur, String prev) {
        Map<String, Integer> strength = Map.of("reject", 3, "quarantine", 2, "none", 1);
        // Map.of() imutável não aceita chave null — normalizar antes do lookup
        int curScore  = cur  != null ? strength.getOrDefault(cur.toLowerCase(),  0) : 0;
        int prevScore = prev != null ? strength.getOrDefault(prev.toLowerCase(), 0) : 0;
        return curScore > prevScore;
    }

    private int riskLevel(String risk) {
        return switch (risk != null ? risk.toUpperCase() : "") {
            case "CRITICAL" -> 4;
            case "HIGH"     -> 3;
            case "MEDIUM"   -> 2;
            case "LOW"      -> 1;
            default         -> 0;
        };
    }

    private int severityOrder(String sev) {
        return switch (sev != null ? sev.toUpperCase() : "") {
            case "CRITICAL" -> 0;
            case "HIGH"     -> 1;
            case "MEDIUM"   -> 2;
            case "LOW"      -> 3;
            default         -> 4;
        };
    }

    private Set<String> methodSet(List<HttpMethodFinding> methods) {
        if (methods == null) return Set.of();
        return methods.stream().map(HttpMethodFinding::getMethod).collect(Collectors.toSet());
    }

    private Set<Integer> portSet(List<PortFinding> ports) {
        if (ports == null) return Set.of();
        return ports.stream().map(PortFinding::getPort).collect(Collectors.toSet());
    }

    private Set<String> fileSet(List<SensitiveFileFinding> files) {
        if (files == null) return Set.of();
        return files.stream()
                .filter(f -> "EXPOSED".equals(f.getExposure()))
                .map(SensitiveFileFinding::getPath)
                .collect(Collectors.toSet());
    }

    private <T> Set<T> setDiff(Set<T> a, Set<T> b) {
        Set<T> diff = new HashSet<>(a);
        diff.removeAll(b);
        return diff;
    }
}