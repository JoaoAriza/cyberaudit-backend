package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.GraphQlIntrospectionFinding;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class GraphQlIntrospectionService {

    /**
     * Query minima de introspection — retorna todos os tipos do schema.
     * Usada para confirmar se introspection esta habilitada em producao.
     */
    private static final String INTROSPECTION_QUERY =
            "{\"query\":\"{__schema{types{name}}}\"}";

    /** Paths comuns de endpoints GraphQL */
    private static final List<String> GRAPHQL_PATHS = List.of(
            "/graphql",
            "/api/graphql",
            "/v1/graphql",
            "/graphql/v1",
            "/graphql/v2",
            "/api/v1/graphql",
            "/api/v2/graphql",
            "/query",
            "/api/query",
            "/gql",
            "/api/gql"
    );

    /**
     * Strings presentes em UIs interativas de GraphQL.
     * GraphiQL e GraphQL Playground sao as mais comuns.
     */
    private static final List<String> PLAYGROUND_MARKERS = List.of(
            "graphiql",
            "graphql-playground",
            "graphql playground",
            "graphql voyager",
            "altair graphql"
    );

    private static final Pattern TYPE_COUNT_PATTERN =
            Pattern.compile("\"name\"\\s*:", Pattern.CASE_INSENSITIVE);

    private final HttpClient client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)  // redirects seguidos por ScannerHttp.sendFollowingSafely (revalida cada hop)
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    public List<GraphQlIntrospectionFinding> scan(String baseUrl) {
        List<GraphQlIntrospectionFinding> findings = new ArrayList<>();
        String base = extractBase(baseUrl);
        if (base == null) return findings;

        for (String path : GRAPHQL_PATHS) {
            GraphQlIntrospectionFinding finding = probe(base, path);
            if (finding != null) {
                findings.add(finding);
                // Encontrou GraphQL — nao precisa testar outros paths
                // (o endpoint real ja foi confirmado, evita duplicatas)
                break;
            }
        }

        return findings;
    }

    private GraphQlIntrospectionFinding probe(String base, String path) {
        String url = base + path;

        // Passo 1: verificar se e um endpoint GraphQL e se aceita introspection
        boolean introspectionEnabled = false;
        int     typeCount            = -1;
        String  introspectionEvidence = null;

        try {
            HttpRequest introspectionReq = HttpRequest.newBuilder(URI.create(url))
                    .POST(HttpRequest.BodyPublishers.ofString(INTROSPECTION_QUERY))
                    .timeout(Duration.ofSeconds(8))
                    .header("Content-Type", "application/json")
                    .header("User-Agent", ScannerHttp.USER_AGENT)
                    .header("Accept", "application/json")
                    .build();

            HttpResponse<String> resp = ScannerHttp.sendFollowingSafely(client, 
                    introspectionReq, ScannerHttp.limitedString());

            String body        = resp.body() == null ? "" : resp.body();
            String lower       = body.toLowerCase(Locale.ROOT);
            String contentType = resp.headers()
                    .firstValue("content-type").orElse("").toLowerCase(Locale.ROOT);

            // Confirma: HTTP 200, JSON, schema presente na resposta
            if (resp.statusCode() == 200
                    && (contentType.contains("application/json") || lower.trim().startsWith("{"))
                    && lower.contains("\"__schema\"")
                    && lower.contains("\"types\"")) {

                introspectionEnabled  = true;
                typeCount             = countTypes(body);
                // Extrai um snippet limitado como evidencia
                int idx = lower.indexOf("\"__schema\"");
                introspectionEvidence = body.substring(idx, Math.min(idx + 80, body.length()))
                        .replaceAll("[\\r\\n\\t]+", " ").trim() + "...";
            }
        } catch (Exception ignored) {}

        // Passo 2: verificar se ha interface interativa (GraphiQL / Playground)
        // via GET para o mesmo endpoint — essas UIs servem HTML quando chamadas sem JSON
        boolean playgroundExposed  = false;
        String  playgroundEvidence = null;

        try {
            HttpRequest getReq = HttpRequest.newBuilder(URI.create(url))
                    .GET()
                    .timeout(Duration.ofSeconds(6))
                    .header("User-Agent", ScannerHttp.USER_AGENT)
                    .header("Accept", "text/html,application/xhtml+xml,*/*")
                    .build();

            HttpResponse<String> getResp = ScannerHttp.sendFollowingSafely(client, 
                    getReq, ScannerHttp.limitedString());

            if (getResp.statusCode() == 200) {
                String getBody  = getResp.body() == null ? "" : getResp.body();
                String getLower = getBody.toLowerCase(Locale.ROOT);
                String ct       = getResp.headers()
                        .firstValue("content-type").orElse("").toLowerCase(Locale.ROOT);

                // So considera playground se o response for HTML (nao JSON)
                if (ct.contains("text/html") || getLower.contains("<!doctype html")) {
                    for (String marker : PLAYGROUND_MARKERS) {
                        if (getLower.contains(marker)) {
                            playgroundExposed  = true;
                            playgroundEvidence = "UI marker: \"" + marker + "\"";
                            break;
                        }
                    }
                }
            }
        } catch (Exception ignored) {}

        // Nao reportar se nada foi encontrado
        if (!introspectionEnabled && !playgroundExposed) return null;

        String severity = resolveSeverity(introspectionEnabled, playgroundExposed);
        String evidence = buildEvidence(introspectionEnabled, playgroundExposed,
                introspectionEvidence, playgroundEvidence, typeCount);

        return GraphQlIntrospectionFinding.builder()
                .endpoint(path)
                .introspectionEnabled(introspectionEnabled)
                .playgroundExposed(playgroundExposed)
                .typeCount(typeCount)
                .severity(severity)
                .evidence(evidence)
                .build();
    }

    /**
     * Conta o numero de tipos no schema contando ocorrencias de "name":
     * em objetos dentro de "types". Heuristico mas suficientemente preciso.
     */
    private int countTypes(String body) {
        try {
            int schemaIdx = body.indexOf("\"__schema\"");
            if (schemaIdx < 0) return -1;
            String schemaSection = body.substring(schemaIdx);
            Matcher m = TYPE_COUNT_PATTERN.matcher(schemaSection);
            int count = 0;
            while (m.find()) count++;
            return count;
        } catch (Exception e) {
            return -1;
        }
    }

    private String resolveSeverity(boolean introspection, boolean playground) {
        if (playground)    return "HIGH";    // UI interativa = maior superficie
        if (introspection) return "MEDIUM";  // Schema exposto mas so via API
        return "LOW";
    }

    private String buildEvidence(boolean introspection, boolean playground,
                                  String introspEv, String playgroundEv, int typeCount) {
        List<String> parts = new ArrayList<>();
        if (introspection) {
            String tc = typeCount > 0 ? " (" + typeCount + " tipos)" : "";
            parts.add("Introspection habilitada" + tc);
            if (introspEv != null) parts.add(introspEv);
        }
        if (playground && playgroundEv != null) parts.add(playgroundEv);
        return String.join(" | ", parts);
    }

    private String extractBase(String url) {
        try {
            URI uri  = URI.create(url);
            int port = uri.getPort();
            if (port > 0 && port != 80 && port != 443)
                return uri.getScheme() + "://" + uri.getHost() + ":" + port;
            return uri.getScheme() + "://" + uri.getHost();
        } catch (Exception e) { return null; }
    }
}
