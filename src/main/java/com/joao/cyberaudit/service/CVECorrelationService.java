package com.joao.cyberaudit.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.joao.cyberaudit.model.CVEFinding;
import com.joao.cyberaudit.model.TechFingerprintResult;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class CVECorrelationService {

    private static final String NVD_API     = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    private static final int    MAX_PER_SW  = 5;
    private static final int    MAX_TOTAL   = 15;
    private static final int    MAX_QUERIES = 4;
    private static final long   DELAY_MS    = 700;

    /**
     * Mapa de aliases: nome interno → nome que o NVD usa nas descrições.
     * Crítico para obter resultados corretos — o NVD usa nomes completos,
     * não siglas (ex: "IIS" não encontra nada, "Internet Information Services" encontra).
     */
    private static final Map<String, String> NVD_ALIASES;
    static {
        NVD_ALIASES = new LinkedHashMap<>();
        NVD_ALIASES.put("Microsoft IIS",         "Internet Information Services");
        NVD_ALIASES.put("Apache HTTP Server",    "Apache HTTP Server");
        NVD_ALIASES.put("nginx",                 "nginx");
        NVD_ALIASES.put("OpenResty",             "OpenResty");
        NVD_ALIASES.put("Lighttpd",              "Lighttpd");
        NVD_ALIASES.put("Caddy",                 "Caddy");
        NVD_ALIASES.put("PHP",                   "PHP");
        NVD_ALIASES.put("ASP.NET",               "ASP.NET");
        NVD_ALIASES.put("WordPress",             "WordPress");
        NVD_ALIASES.put("Drupal",                "Drupal");
        NVD_ALIASES.put("Joomla",                "Joomla");
        NVD_ALIASES.put("Ghost",                 "Ghost CMS");
        NVD_ALIASES.put("jQuery",                "jQuery");
        NVD_ALIASES.put("Angular",               "Angular");
        NVD_ALIASES.put("Next.js",               "Next.js");
        NVD_ALIASES.put("Nuxt.js",               "Nuxt.js");
        NVD_ALIASES.put("Laravel",               "Laravel");
        NVD_ALIASES.put("Django",                "Django");
        NVD_ALIASES.put("Ruby on Rails",         "Ruby on Rails");
        NVD_ALIASES.put("Java Servlet/Tomcat",   "Apache Tomcat");
    }

    private final HttpClient   client  = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10)).build();
    private final ObjectMapper jackson = new ObjectMapper();

    public List<CVEFinding> correlate(TechFingerprintResult fingerprint) {
        if (fingerprint == null) return List.of();

        Map<String, String> versions = fingerprint.getDetectedVersions();
        if (versions == null || versions.isEmpty()) return List.of();

        List<CVEFinding> findings = new ArrayList<>();
        int queryCount = 0;

        for (Map.Entry<String, String> entry : versions.entrySet()) {
            if (queryCount >= MAX_QUERIES || findings.size() >= MAX_TOTAL) break;

            String software = entry.getKey();
            String version  = entry.getValue();

            List<CVEFinding> cves = queryNvd(software, version);
            findings.addAll(cves);
            queryCount++;

            if (queryCount < Math.min(versions.size(), MAX_QUERIES)) {
                try { Thread.sleep(DELAY_MS); } catch (InterruptedException ignored) {}
            }
        }

        findings.sort((a, b) -> Double.compare(b.getCvssScore(), a.getCvssScore()));
        return findings.stream().limit(MAX_TOTAL).collect(Collectors.toList());
    }

    private List<CVEFinding> queryNvd(String software, String version) {
        try {
            // Usa o nome NVD correto se disponível, senão usa o nome original
            String nvdName = NVD_ALIASES.getOrDefault(software, software);
            String keyword = nvdName + " " + version;
            String encoded = URLEncoder.encode(keyword, StandardCharsets.UTF_8);
            String url = NVD_API + "?keywordSearch=" + encoded
                    + "&resultsPerPage=" + MAX_PER_SW;

            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .GET()
                    .timeout(Duration.ofSeconds(12))
                    .header("User-Agent", "CyberAuditScanner/1.0")
                    .header("Accept", "application/json")
                    .build();

            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());

            if (resp.statusCode() == 429) {
                // Rate limit — aguarda e tenta uma vez mais
                Thread.sleep(3000);
                resp = client.send(req, HttpResponse.BodyHandlers.ofString());
            }

            if (resp.statusCode() != 200) return List.of();

            // Se não encontrou com versão, tenta sem versão (só nome do software)
            List<CVEFinding> results = parseResponse(resp.body(), software + " " + version);
            return results;

        } catch (Exception e) {
            return List.of();
        }
    }

    private List<CVEFinding> parseResponse(String json, String affectedSoftware) {
        List<CVEFinding> findings = new ArrayList<>();
        try {
            JsonNode root  = jackson.readTree(json);
            JsonNode vulns = root.path("vulnerabilities");
            if (!vulns.isArray()) return List.of();

            for (JsonNode vuln : vulns) {
                JsonNode cve = vuln.path("cve");
                if (cve.isMissingNode()) continue;

                String id = cve.path("id").asText("");
                if (id.isBlank()) continue;

                // Descrição em inglês
                String description = "";
                for (JsonNode desc : cve.path("descriptions")) {
                    if ("en".equals(desc.path("lang").asText())) {
                        description = desc.path("value").asText("");
                        break;
                    }
                }
                if (description.length() > 300)
                    description = description.substring(0, 297) + "...";

                // CVSS: tenta v3.1 → v3.0 → v2
                double cvssScore = 0.0;
                String severity  = "UNKNOWN";

                JsonNode metrics = cve.path("metrics");
                JsonNode v31 = metrics.path("cvssMetricV31");
                JsonNode v30 = metrics.path("cvssMetricV30");
                JsonNode v2  = metrics.path("cvssMetricV2");

                JsonNode metricNode =
                        v31.isArray() && v31.size() > 0 ? v31.get(0) :
                                v30.isArray() && v30.size() > 0 ? v30.get(0) :
                                        v2.isArray()  && v2.size()  > 0 ? v2.get(0)  : null;

                if (metricNode != null) {
                    JsonNode cvssData = metricNode.path("cvssData");
                    cvssScore = cvssData.path("baseScore").asDouble(0.0);
                    severity  = cvssData.path("baseSeverity")
                            .asText(metricNode.path("baseSeverity").asText("UNKNOWN"))
                            .toUpperCase();
                }

                String published = cve.path("published").asText("").split("T")[0];
                String refUrl    = "https://nvd.nist.gov/vuln/detail/" + id;

                findings.add(CVEFinding.builder()
                        .cveId(id)
                        .severity(severity)
                        .cvssScore(cvssScore)
                        .description(description)
                        .affectedSoftware(affectedSoftware)
                        .publishedDate(published)
                        .referenceUrl(refUrl)
                        .build());
            }
        } catch (Exception ignored) {}
        return findings;
    }
}