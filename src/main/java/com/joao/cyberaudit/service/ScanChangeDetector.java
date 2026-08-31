package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.*;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Compara dois ScanResult (atual vs anterior) e retorna a lista de mudanças.
 * Detecta melhorias, regressões e alterações neutras que um analista
 * precisaria saber entre dois scans do mesmo alvo.
 *
 * <h2>{@code field} não é traduzido — é rótulo técnico</h2>
 *
 * {@code description}, {@code oldValue} e {@code newValue} saem do catálogo e seguem
 * o idioma do laudo. {@code field} não, e isso é decisão, não esquecimento:
 *
 * <ul>
 *   <li>metade dos valores é dado cru que não tem tradução — o nome do header
 *       ({@code Strict-Transport-Security}), o método ({@code TRACE}), o caminho do
 *       arquivo exposto, o número da porta, o nome da tecnologia;</li>
 *   <li>as duas telas renderizam a coluna em fonte monoespaçada, colada ao
 *       {@code category}, que também é código não traduzido ({@code SSL},
 *       {@code HEADERS});</li>
 *   <li>no PDF sai como {@code SSL / certificate validity}, e o PDF é inglês por
 *       decisão de produto — ali o texto atual já está correto.</li>
 * </ul>
 *
 * Traduzir só a metade que é prosa deixaria a coluna metade em cada regime. Quem
 * mudar de ideia precisa mover as duas metades, não uma —
 * {@code ScanChangeDetectorI18nTest.fieldNaoSegueOIdioma()} trava isso.
 */
@Service
public class ScanChangeDetector {

    private final MessageCatalog catalog;

    public ScanChangeDetector(MessageCatalog catalog) {
        this.catalog = catalog;
    }

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
                // Duas chaves em vez de uma com o verbo interpolado: "subiu"/"caiu"
                // são texto, e texto interpolado não passa por tradutor nenhum.
                .description(delta > 0
                        ? catalog.change("SCORE_UP",   prevScore, curScore, delta)
                        : catalog.change("SCORE_DOWN", prevScore, curScore, delta))
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
                    .oldValue(catalog.valor(prevSsl.isValid() ? "valido" : "invalido"))
                    .newValue(catalog.valor(curSsl.isValid()  ? "valido" : "invalido"))
                    .severity(degraded ? "HIGH" : "MEDIUM")
                    .description(degraded
                            ? catalog.change("SSL_INVALID")
                            : catalog.change("SSL_VALID_AGAIN"))
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
                    .description(catalog.change("SSL_NEW_CERT"))
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
                    .oldValue(catalog.valor("dias", prevDays))
                    .newValue(catalog.valor("dias", curDays))
                    .severity("HIGH")
                    .description(catalog.change("SSL_WINDOW_30"))
                    .build());
        } else if (prevDays > 90 && curDays <= 90 && curDays > 30) {
            out.add(ScanChange.builder()
                    .category("SSL")
                    .field("days remaining")
                    .changeType("DEGRADED")
                    .oldValue(catalog.valor("dias", prevDays))
                    .newValue(catalog.valor("dias", curDays))
                    .severity("MEDIUM")
                    .description(catalog.change("SSL_WINDOW_90"))
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
                description = catalog.change("HEADER_ADDED", header);
            } else if (wasOk && nowMiss) {
                changeType  = "DEGRADED";
                severity    = criticalHeader(header) ? "HIGH" : "MEDIUM";
                description = catalog.change("HEADER_REMOVED", header);
            } else if (!Objects.equals(curVal, prevVal)) {
                changeType  = "CHANGED";
                severity    = "LOW";
                description = catalog.change("HEADER_CHANGED", header);
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
                .oldValue(catalog.valor(prevWaf ? "detectado" : "naoDetectado"))
                .newValue(catalog.valor(curWaf  ? "detectado" : "naoDetectado"))
                .severity(curWaf ? "LOW" : "MEDIUM")
                .description(curWaf
                        ? catalog.change("WAF_DETECTED", cur.getWafDetectionResult().getProvider())
                        : catalog.change("WAF_GONE"))
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
                    .description(catalog.change("SPF_CHANGED"))
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
                    .description(catalog.change("DMARC_CHANGED", prevDns.getDmarcPolicy(),
                            curDns.getDmarcPolicy()))
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
                    .description(catalog.change("SPOOFING_RISK",
                            prevDns.getEmailSpoofingRisk(), curDns.getEmailSpoofingRisk()))
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
                    .oldValue(catalog.valor("naoDetectado"))
                    .newValue(catalog.valor("habilitado"))
                    .severity("HIGH")
                    .description(catalog.change("HTTP_METHOD_NEW", m))
                    .build());
        }

        // Métodos que sumiram
        for (String m : setDiff(prevMethods, curMethods)) {
            out.add(ScanChange.builder()
                    .category("HTTP METHODS")
                    .field(m)
                    .changeType("IMPROVED")
                    .oldValue(catalog.valor("habilitado"))
                    .newValue(catalog.valor("naoDetectado"))
                    .severity("LOW")
                    .description(catalog.change("HTTP_METHOD_GONE", m))
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
                    .oldValue(catalog.valor("fechada"))
                    .newValue(catalog.valor("aberta"))
                    .severity("HIGH")
                    .description(catalog.change("PORT_OPENED", port))
                    .build());
        }

        for (int port : setDiff(prevPorts, curPorts)) {
            out.add(ScanChange.builder()
                    .category("PORTS")
                    .field("port " + port)
                    .changeType("IMPROVED")
                    .oldValue(catalog.valor("aberta"))
                    .newValue(catalog.valor("fechada"))
                    .severity("LOW")
                    .description(catalog.change("PORT_CLOSED", port))
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
                    .oldValue(catalog.valor("naoExposto"))
                    .newValue(catalog.valor("exposto"))
                    .severity("HIGH")
                    .description(catalog.change("FILE_EXPOSED", f))
                    .build());
        }

        for (String f : setDiff(prevFiles, curFiles)) {
            out.add(ScanChange.builder()
                    .category("FILES")
                    .field(f)
                    .changeType("IMPROVED")
                    .oldValue(catalog.valor("exposto"))
                    .newValue(catalog.valor("naoDetectado"))
                    .severity("LOW")
                    .description(catalog.change("FILE_GONE", f))
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
                .oldValue(catalog.valor(prev.isServerVersionExposed() ? "exposto" : "oculto"))
                .newValue(catalog.valor(cur.isServerVersionExposed()  ? "exposto" : "oculto"))
                .severity(cur.isServerVersionExposed() ? "MEDIUM" : "LOW")
                .description(cur.isServerVersionExposed()
                        ? catalog.change("SERVER_EXPOSED")
                        : catalog.change("SERVER_HIDDEN"))
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
                .oldValue(prevVal != null ? prevVal : catalog.valor("naoDetectado"))
                .newValue(curVal)
                .severity("INFO")
                .description(catalog.change("TECH_CHANGED", label,
                        prevVal != null ? prevVal : catalog.valor("naoDetectado"), curVal))
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