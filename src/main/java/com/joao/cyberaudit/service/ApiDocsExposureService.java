package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.ApiDocsExposureFinding;
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
public class ApiDocsExposureService {

    /**
     * Paths a verificar, agrupados por tipo esperado de conteudo.
     *
     * Cada entrada: { path, type, descricao }
     * Tipo determina quais marcadores de conteudo serao checados e a severidade.
     */
    private record DocTarget(String path, String type) {}

    private static final List<DocTarget> TARGETS = List.of(
            // Swagger UI (interface interativa)
            new DocTarget("/swagger-ui.html",              "SWAGGER_UI"),
            new DocTarget("/swagger-ui/",                  "SWAGGER_UI"),
            new DocTarget("/swagger-ui/index.html",        "SWAGGER_UI"),
            new DocTarget("/swagger",                      "SWAGGER_UI"),
            // Springfox legacy
            new DocTarget("/webjars/springfox-swagger-ui/swagger-ui.html", "SWAGGER_UI"),

            // OpenAPI / Swagger spec JSON — expoe schema completo da API
            new DocTarget("/v3/api-docs",                  "OPENAPI_JSON"),  // Springdoc (OpenAPI 3)
            new DocTarget("/v2/api-docs",                  "OPENAPI_JSON"),  // Springfox (Swagger 2)
            new DocTarget("/api-docs",                     "OPENAPI_JSON"),
            new DocTarget("/openapi.json",                 "OPENAPI_JSON"),
            new DocTarget("/api/openapi.json",             "OPENAPI_JSON"),
            new DocTarget("/api/v1/openapi.json",          "OPENAPI_JSON"),

            // OpenAPI YAML
            new DocTarget("/openapi.yaml",                 "OPENAPI_YAML"),
            new DocTarget("/openapi.yml",                  "OPENAPI_YAML"),
            new DocTarget("/api/openapi.yaml",             "OPENAPI_YAML"),

            // ReDoc
            new DocTarget("/redoc",                        "REDOC"),
            new DocTarget("/api/redoc",                    "REDOC"),

            // Endpoints genericos de docs
            new DocTarget("/docs",                         "API_DOCS"),
            new DocTarget("/api/docs",                     "API_DOCS"),
            new DocTarget("/api-explorer",                 "API_DOCS")
    );

    private final HttpClient client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NORMAL)
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    public List<ApiDocsExposureFinding> scan(String baseUrl) {
        List<ApiDocsExposureFinding> findings = new ArrayList<>();
        String base = extractBase(baseUrl);
        if (base == null) return findings;

        for (DocTarget target : TARGETS) {
            ApiDocsExposureFinding finding = probe(base, target);
            if (finding != null) findings.add(finding);
        }

        return findings;
    }

    private ApiDocsExposureFinding probe(String base, DocTarget target) {
        try {
            String url = base + target.path();

            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .GET()
                    .timeout(Duration.ofSeconds(6))
                    .header("User-Agent", "Mozilla/5.0 CyberAuditScanner/1.0")
                    .header("Accept", "text/html,application/json,application/yaml,*/*")
                    .build();

            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());

            if (resp.statusCode() != 200) return null;

            String body  = resp.body() == null ? "" : resp.body();
            String lower = body.toLowerCase(Locale.ROOT);
            String contentType = resp.headers()
                    .firstValue("content-type").orElse("").toLowerCase(Locale.ROOT);

            String evidence = matchEvidence(target.type(), lower, contentType);
            if (evidence == null) return null;  // 200 mas sem marcadores — FP, descartar

            return ApiDocsExposureFinding.builder()
                    .path(target.path())
                    .type(target.type())
                    .severity(resolveSeverity(target.type()))
                    .evidence(evidence)
                    .description(buildDescription(target.type(), target.path()))
                    .build();

        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Verifica se o body contem marcadores especificos do tipo esperado.
     * Retorna o trecho de evidencia ou null se nao confirmado.
     *
     * Essa verificacao e critica para evitar falsos positivos:
     * SPAs como Next.js e Nuxt retornam HTTP 200 para qualquer path com HTML generico.
     * Exigimos marcadores especificos que so aparecem em docs reais.
     */
    private String matchEvidence(String type, String lower, String contentType) {
        return switch (type) {
            case "SWAGGER_UI" -> {
                // Swagger UI real contem o bundle JS ou titulos especificos
                if (lower.contains("swaggeruibundle") || lower.contains("swagger-ui-bundle"))
                    yield "SwaggerUIBundle detectado";
                if (lower.contains("swagger-ui") && lower.contains("<title"))
                    yield "Swagger UI HTML detectado";
                if (lower.contains("\"swagger\"") && lower.contains("\"paths\""))
                    yield "Swagger spec inline detectado";
                yield null;
            }
            case "OPENAPI_JSON" -> {
                // OpenAPI JSON: precisa de "openapi" ou "swagger" + "paths" + "info"
                // Evita match em qualquer JSON que tenha essas palavras em outro contexto
                boolean hasSpec = (lower.contains("\"openapi\"") || lower.contains("\"swagger\""))
                        && lower.contains("\"paths\"")
                        && lower.contains("\"info\"");
                if (!hasSpec) yield null;
                boolean isJson = contentType.contains("application/json") || lower.trim().startsWith("{");
                if (!isJson) yield null;
                if (lower.contains("\"openapi\"")) yield "OpenAPI 3.x spec JSON exposta";
                yield "Swagger 2.x spec JSON exposta";
            }
            case "OPENAPI_YAML" -> {
                // YAML: comeca com "openapi:" ou "swagger:" e contem "paths:"
                if ((lower.startsWith("openapi:") || lower.startsWith("swagger:"))
                        && lower.contains("paths:"))
                    yield "OpenAPI spec YAML exposta";
                // Pode ter espacos/newlines antes
                if (lower.contains("\nopenapi:") || lower.contains("\nswagger:"))
                    yield "OpenAPI spec YAML exposta";
                yield null;
            }
            case "REDOC" -> {
                if (lower.contains("redoc") && (lower.contains("redocly") ||
                        lower.contains("<redoc ") || lower.contains("redoc.standalone")))
                    yield "ReDoc interface detectada";
                yield null;
            }
            case "API_DOCS" -> {
                // Docs genericos: exige multiplos indicadores para evitar FP
                int score = 0;
                if (lower.contains("\"openapi\"") || lower.contains("\"swagger\"")) score++;
                if (lower.contains("\"paths\""))   score++;
                if (lower.contains("\"info\""))    score++;
                if (lower.contains("swagger-ui") || lower.contains("redoc")) score++;
                if (score >= 2) yield "Documentacao de API detectada (score=" + score + ")";
                yield null;
            }
            default -> null;
        };
    }

    private String resolveSeverity(String type) {
        return switch (type) {
            // Specs JSON/YAML expoe o schema completo: todos os endpoints, parametros,
            // modelos de dados — HIGH pois facilita ataques direcionados
            case "OPENAPI_JSON", "OPENAPI_YAML" -> "HIGH";
            // UIs sao informativas mas visualmente acessiveis
            default -> "MEDIUM";
        };
    }

    private String buildDescription(String type, String path) {
        return switch (type) {
            case "SWAGGER_UI"   -> "Swagger UI acessivel publicamente em " + path +
                    ". Permite explorar e testar endpoints da API sem autenticacao.";
            case "OPENAPI_JSON" -> "Especificacao OpenAPI/Swagger em JSON exposta em " + path +
                    ". Contem schema completo: endpoints, parametros, modelos e metodos HTTP.";
            case "OPENAPI_YAML" -> "Especificacao OpenAPI em YAML exposta em " + path +
                    ". Equivalente ao JSON — schema completo da API acessivel publicamente.";
            case "REDOC"        -> "Interface ReDoc de documentacao acessivel em " + path +
                    ". Expoe estrutura completa da API de forma navegavel.";
            default             -> "Endpoint de documentacao de API detectado em " + path + ".";
        };
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
