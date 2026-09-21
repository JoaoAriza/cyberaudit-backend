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

        // O SO do ALVO decide uma vez, no início: é o mesmo para todos os CVEs deste
        // scan e não muda entre consultas.
        Plataforma alvo = plataformaDoAlvo(fingerprint);

        List<CVEFinding> findings = new ArrayList<>();
        int queryCount = 0;

        for (Map.Entry<String, String> entry : versions.entrySet()) {
            if (queryCount >= MAX_QUERIES || findings.size() >= MAX_TOTAL) break;

            String software = entry.getKey();
            String version  = entry.getValue();

            // Sem versão detectada — busca por CPE sem versão retornaria TODOS os CVEs
            // do produto (ruído massivo). Pulamos.
            if (version == null || version.isBlank()) continue;

            List<CVEFinding> cves = queryByCpe(software, version, alvo);
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
    private List<CVEFinding> queryByCpe(String software, String version, Plataforma alvo) {
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

            HttpResponse<String> resp = client.send(req, ScannerHttp.limitedString(ScannerHttp.MAX_JSON_BODY_BYTES));

            if (resp.statusCode() == 429) {
                Thread.sleep(3000);
                resp = client.send(req, ScannerHttp.limitedString(ScannerHttp.MAX_JSON_BODY_BYTES));
            }

            if (resp.statusCode() != 200) return List.of();

            return parseResponse(resp.body(), software + " " + ver, alvo);

        } catch (Exception e) {
            return List.of();
        }
    }

    private List<CVEFinding> parseResponse(String json, String affectedSoftware, Plataforma alvo) {
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

                // Filtro de plataforma: um CVE cuja config no NVD exige um SO que o
                // alvo comprovadamente NÃO é não se aplica. Foi o que gerou o falso
                // positivo CVE-2024-3566 (CVSS 9.8) — command injection via
                // CreateProcess do Windows — reportado num Apache/PHP em Linux.
                if (!cveSeAplica(soExigidoPeloCve(cve), alvo)) continue;

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

    // ── Filtro de plataforma ────────────────────────────────────────────────────

    /**
     * Sistema operacional, do lado do ALVO e do lado do CVE.
     *
     * {@code DESCONHECIDA} tem sentidos diferentes nos dois lados, de propósito: no
     * alvo é "não deu para dizer"; no CVE é "sem restrição de SO" — vale em qualquer
     * um. É o {@link #cveSeAplica} que junta os dois com a assimetria certa.
     */
    enum Plataforma { WINDOWS, UNIX, DESCONHECIDA }

    /** Marcadores de Windows na pilha detectada — IIS, ASP.NET, Server com Win32/64. */
    private static final List<String> MARCADORES_WINDOWS = List.of(
            "iis", "asp.net", "aspnet", "win32", "win64", "windows");

    /** Marcadores de Unix — quase sempre no parêntese do header Server (ex.: "(Ubuntu)"). */
    private static final List<String> MARCADORES_UNIX = List.of(
            "ubuntu", "debian", "centos", "red hat", "redhat", "rhel", "fedora",
            "linux", "unix", "freebsd", "openbsd", "netbsd", "amzn", "alma",
            "rocky", "gentoo", "suse", "cloudlinux");

    /**
     * O SO do alvo, inferido do fingerprint.
     *
     * Windows deixa rastro claro (IIS, ASP.NET, "Win64" no Server); Unix costuma
     * aparecer no parêntese do header Server. Sem nenhum dos dois, {@code DESCONHECIDA}.
     */
    Plataforma plataformaDoAlvo(TechFingerprintResult fp) {
        if (fp == null) return Plataforma.DESCONHECIDA;

        StringBuilder sb = new StringBuilder();
        for (String s : new String[]{fp.getWebServer(), fp.getBackend(), fp.getFramework(),
                fp.getCms(), fp.getLanguage(), fp.getCdn()}) {
            if (s != null) sb.append(s).append(' ');
        }
        if (fp.getLibraries() != null) fp.getLibraries().forEach(l -> sb.append(l).append(' '));
        if (fp.getEvidence()  != null) fp.getEvidence().forEach(e -> sb.append(e).append(' '));
        String blob = sb.toString().toLowerCase(Locale.ROOT);

        // Windows tem precedência: se há sinal dos dois (raro), o positivo de Windows
        // é o mais específico e o que evita descartar um CVE Windows por engano.
        if (MARCADORES_WINDOWS.stream().anyMatch(blob::contains)) return Plataforma.WINDOWS;
        if (MARCADORES_UNIX.stream().anyMatch(blob::contains))    return Plataforma.UNIX;
        return Plataforma.DESCONHECIDA;
    }

    /**
     * O SO que a config do CVE exige — lido só dos CPEs de SO ({@code part = o}).
     *
     * É o vínculo de plataforma confiável do NVD: o CVE-2024-3566 traz
     * {@code cpe:2.3:o:microsoft:windows} num AND com o runtime, dizendo "só vale
     * rodando em Windows". Não uso descrição nem {@code target_sw} de propósito —
     * descrição é texto solto e {@code target_sw} carrega coisas que não são SO
     * (ex.: {@code wordpress}), e um palpite errado aqui DESCARTA um CVE real.
     *
     * {@code WINDOWS} = todos os CPEs de SO são Windows. {@code UNIX} = todos são
     * não-Windows. Config sem CPE de SO, ou multiplataforma (tem os dois), volta
     * {@code DESCONHECIDA} — sem restrição, aplica em qualquer alvo.
     */
    Plataforma soExigidoPeloCve(JsonNode cve) {
        List<String> criterios = new ArrayList<>();
        coletarCriteria(cve, criterios);

        boolean temWindows = false, temNaoWindows = false;
        for (String c : criterios) {
            Plataforma fam = familiaDoCpeOs(c);
            if      (fam == Plataforma.WINDOWS) temWindows = true;
            else if (fam == Plataforma.UNIX)    temNaoWindows = true;
        }

        if (temWindows && !temNaoWindows) return Plataforma.WINDOWS;
        if (temNaoWindows && !temWindows) return Plataforma.UNIX;
        return Plataforma.DESCONHECIDA;
    }

    /**
     * O CVE se aplica a este alvo?
     *
     * A assimetria é o ponto: um CVE exclusivo de Windows exige que o alvo SEJA
     * Windows — e Windows se anuncia, então ausência de sinal já é forte indício de
     * que não é, e o CVE cai. Um CVE exclusivo de não-Windows, ao contrário, só cai
     * quando o alvo é comprovadamente Windows: Unix é o caso comum e costuma vir sem
     * marcador, então "desconhecido" continua valendo o CVE. Descartar é sempre a
     * exceção — o custo de esconder um CVE real é maior que o de mostrar um duvidoso.
     */
    boolean cveSeAplica(Plataforma exigidoPeloCve, Plataforma alvo) {
        if (exigidoPeloCve == Plataforma.DESCONHECIDA) return true;   // sem restrição de SO
        if (exigidoPeloCve == Plataforma.WINDOWS)      return alvo == Plataforma.WINDOWS;
        return alvo != Plataforma.WINDOWS;                            // exige não-Windows
    }

    /** Família do CPE quando ele é de SISTEMA OPERACIONAL ({@code part = o}); senão null. */
    private Plataforma familiaDoCpeOs(String criteria) {
        String[] p = criteria.split(":");
        // cpe : 2.3 : part : vendor : product : ...
        if (p.length < 5 || !"o".equals(p[2])) return null;
        boolean windows = "microsoft".equals(p[3]) && p[4].startsWith("windows");
        return windows ? Plataforma.WINDOWS : Plataforma.UNIX;
    }

    /** Junta todo {@code criteria} de qualquer profundidade da árvore do CVE. */
    private void coletarCriteria(JsonNode node, List<String> out) {
        if (node == null || node.isMissingNode()) return;
        if (node.isObject()) {
            JsonNode crit = node.get("criteria");
            if (crit != null && crit.isTextual()) out.add(crit.asText());
            node.forEach(child -> coletarCriteria(child, out));
        } else if (node.isArray()) {
            node.forEach(child -> coletarCriteria(child, out));
        }
    }
}
