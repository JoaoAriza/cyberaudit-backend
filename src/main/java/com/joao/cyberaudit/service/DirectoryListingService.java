package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.DirectoryListingFinding;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

@Service
public class DirectoryListingService {

    /**
     * Diretórios que comumente têm listing habilitado por descuido.
     * Ordenados por severidade — os mais críticos primeiro.
     */
    private static final List<DirTarget> TARGETS = List.of(
            new DirTarget("/uploads/",      "HIGH"),
            new DirTarget("/upload/",       "HIGH"),
            new DirTarget("/files/",        "HIGH"),
            new DirTarget("/backup/",       "CRITICAL"),
            new DirTarget("/backups/",      "CRITICAL"),
            new DirTarget("/logs/",         "HIGH"),
            new DirTarget("/log/",          "HIGH"),
            new DirTarget("/tmp/",          "HIGH"),
            new DirTarget("/temp/",         "HIGH"),
            new DirTarget("/images/",       "MEDIUM"),
            new DirTarget("/img/",          "MEDIUM"),
            new DirTarget("/assets/",       "MEDIUM"),
            new DirTarget("/static/",       "MEDIUM"),
            new DirTarget("/media/",        "MEDIUM"),
            new DirTarget("/docs/",         "MEDIUM"),
            new DirTarget("/data/",         "HIGH"),
            new DirTarget("/export/",       "HIGH"),
            new DirTarget("/exports/",      "HIGH"),
            new DirTarget("/config/",       "CRITICAL"),
            new DirTarget("/configs/",      "CRITICAL")
    );

    /**
     * Padrões que confirmam que o servidor está listando o diretório.
     * Específicos o suficiente para evitar falsos positivos.
     */
    private static final List<String> LISTING_SIGNATURES = List.of(
            "index of /",           // Apache / Nginx padrão
            "directory listing",    // IIS e outros
            "parent directory",     // Apache
            "<title>index of",      // título da página de listing
            "[to parent directory]",// IIS
            "last modified</a>",    // coluna de data no listing Apache
            "directory: /"          // Nginx alternative
    );

    private final HttpClient client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    /**
     * Verifica cada diretório da lista.
     * Retorna apenas os que têm listing confirmado por assinatura no HTML.
     */
    public List<DirectoryListingFinding> scan(String baseUrl) {
        List<DirectoryListingFinding> findings = new ArrayList<>();

        String base = extractBase(baseUrl);
        if (base == null) return findings;

        for (DirTarget target : TARGETS) {
            DirectoryListingFinding finding = probe(base, target);
            if (finding != null) findings.add(finding);
        }

        return findings;
    }

    private DirectoryListingFinding probe(String base, DirTarget target) {
        try {
            String url = base + target.path;

            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .GET()
                    .timeout(Duration.ofSeconds(6))
                    .header("User-Agent", ScannerHttp.USER_AGENT)
                    .build();

            HttpResponse<String> resp = client.send(
                    req, HttpResponse.BodyHandlers.ofString());

            int status = resp.statusCode();

            if (status != 200) return null;

            String body = resp.body() == null ? "" : resp.body();
            String lower = body.toLowerCase(Locale.ROOT);

            String evidence = findSignature(lower);
            if (evidence == null) return null;

            return new DirectoryListingFinding(
                    target.path, status, true,
                    evidence, target.severity
            );

        } catch (Exception e) {
            return null;
        }
    }

    private String findSignature(String lowerBody) {
        for (String sig : LISTING_SIGNATURES) {
            if (lowerBody.contains(sig)) return sig;
        }
        return null;
    }

    private String extractBase(String url) {
        try {
            URI uri  = URI.create(url);
            int port = uri.getPort();
            if (port > 0 && port != 80 && port != 443)
                return uri.getScheme() + "://" + uri.getHost() + ":" + port;
            return uri.getScheme() + "://" + uri.getHost();
        } catch (Exception e) {
            return null;
        }
    }

    private record DirTarget(String path, String severity) {}
}