package com.joao.cyberaudit.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.joao.cyberaudit.model.CVEFinding;
import com.joao.cyberaudit.model.TechFingerprintResult;
import org.springframework.beans.factory.annotation.Value;
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

    private static final String NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    private static final int    MAX_PER_SW  = 5;
    private static final int    MAX_TOTAL   = 15;
    private static final int    MAX_QUERIES = 4;
    private static final long   DELAY_MS    = 700;

    /**
     * CPE map: software name → {vendor, product}
     *
     * Substitui o antigo keywordSearch, que fazia busca full-text e retornava
     * CVEs onde nome/versão aparecia em qualquer parte da descrição — incluindo
     * "fixed in X.Y.Z" ou menções contextuais — gerando alto volume de falsos positivos.
     *
     * Com cpeName, o NVD retorna apenas CVEs cujo "vulnerable configuration"
     * inclui a versão pesquisada (com suporte a ranges: affects >= 1.18.0, < 1.24.1).
     *
     * CPE format: cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*
     * Referência: https://nvd.nist.gov/products/cpe/search
     */
    private static final Map<String, String[]> CPE_MAP;
    static {
        CPE_MAP = new LinkedHashMap<>();
        //                  software name              vendor            product
        CPE_MAP.put("nginx",               new String[]{"nginx",           "nginx"});
        CPE_MAP.put("Apache HTTP Server",  new String[]{"apache",          "http_server"});
        CPE_MAP.put("Microsoft IIS",       new String[]{"microsoft",       "internet_information_services"});
        CPE_MAP.put("Lighttpd",            new String[]{"lighttpd",        "lighttpd"});
        CPE_MAP.put("OpenResty",           new String[]{"openresty",       "openresty"});
        CPE_MAP.put("PHP",                 new String[]{"php",             "php"});
        CPE_MAP.put("WordPress",           new String[]{"wordpress",       "wordpress"});
        CPE_MAP.put("Drupal",              new String[]{"drupal",          "drupal"});
        CPE_MAP.put("Joomla",              new String[]{"joomla",          "joomla"});
        CPE_MAP.put("jQuery",              new String[]{"jquery",          "jquery"});
        CPE_MAP.put("Angular",             new String[]{"google",          "angular"});
        CPE_MAP.put("Laravel",             new String[]{"laravel",         "laravel"});
        CPE_MAP.put("Django",              new String[]{"djangoproject",   "django"});
        CPE_MAP.put("Ruby on Rails",       new String[]{"rubyonrails",     "ruby_on_rails"});
        CPE_MAP.put("Java Servlet/Tomcat", new String[]{"apache",          "tomcat"});
        // ASP.NET e Next.js têm CPE vendors instáveis no NVD — omitidos intencionalmente
        // para não gerar falsos positivos com CPE errado
    }

    private final HttpClient   client  = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10)).build();
    private final ObjectMapper jackson = new ObjectMapper();

    /**
     * Chave da API do NVD (opcional). Com chave, o rate-limit sobe de 5 → 50 req/30s,
     * tornando o DELAY_MS de 700ms adequado e reduzindo drasticamente os 429.
     * Registre em https://nvd.nist.gov/developers/request-an-api-key
     */
    @Value("${nvd.api-key:}")
    private String nvdApiKey;

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

            // Sem versão detectada — busca por CPE sem versão retornaria TODOS os CVEs
            // do produto (ruído massivo). Pulamos.
            if (version == null || version.isBlank()) continue;

            List<CVEFinding> cves = queryByCpe(software, version);
            findings.addAll(cves);
            queryCount++;

            if (queryCount < Math.min(versions.size(), MAX_QUERIES)) {
                try { Thread.sleep(DELAY_MS); } catch (InterruptedException ignored) {}
            }
        }

        findings.sort((a, b) -> Double.compare(b.getCvssScore(), a.getCvssScore()));
        return findings.stream().limit(MAX_TOTAL).collect(Collectors.toList());
    }

    /**
     * Consulta o NVD via cpeName — retorna somente CVEs cujo vulnerable configuration
     * inclui a versão exata (ou um range que a contenha).
     *
     * Elimina a principal causa de falsos positivos: keywordSearch retornava CVEs
     * onde versão/software aparecia em qualquer parte do texto da descrição.
     */
    private List<CVEFinding> queryByCpe(String software, String version) {
        String[] cpe = CPE_MAP.get(software);
        if (cpe == null) {
            // Sem mapeamento CPE confirmado — não arriscamos keyword search
            return List.of();
        }

        // Normaliza versão: remove prefixo 'v', strip whitespace
        String ver = version.replaceFirst("^[vV]", "").trim();
        if (ver.isBlank()) return List.of();

        String cpeName = "cpe:2.3:a:" + cpe[0] + ":" + cpe[1] + ":" + ver
                + ":*:*:*:*:*:*:*";

        try {
            String encoded = URLEncoder.encode(cpeName, StandardCharsets.UTF_8);
            String url = NVD_CVE_API + "?cpeName=" + encoded
                    + "&resultsPerPage=" + MAX_PER_SW;

            HttpRequest.Builder reqBuilder = HttpRequest.newBuilder(URI.create(url))
                    .GET()
                    .timeout(Duration.ofSeconds(12))
                    .header("User-Agent", ScannerHttp.USER_AGENT)
                    .header("Accept", "application/json");
            // Com a chave, o NVD libera 50 req/30s (vs. 5 sem chave) → menos 429.
            if (nvdApiKey != null && !nvdApiKey.isBlank()) {
                reqBuilder.header("apiKey", nvdApiKey);
            }
            HttpRequest req = reqBuilder.build();

            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());

            if (resp.statusCode() == 429) {
                Thread.sleep(3000);
                resp = client.send(req, HttpResponse.BodyHandlers.ofString());
            }

            if (resp.statusCode() != 200) return List.of();

            return parseResponse(resp.body(), software + " " + ver);

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

                // CVEs sem CVSS score são registros incompletos no NVD — ignorar
                if (cvssScore == 0.0) continue;

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
