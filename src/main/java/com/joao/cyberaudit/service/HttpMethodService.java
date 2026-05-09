package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.HttpMethodFinding;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
public class HttpMethodService {

    /**
     * Métodos a testar com seus riscos.
     * GET, POST, HEAD são normais — não testamos.
     * OPTIONS é testado indiretamente pelo CORS probe.
     */
    private static final Map<String, MethodRisk> METHOD_RISKS = Map.of(
            "TRACE",   new MethodRisk("CRITICAL",
                    "TRACE habilitado permite Cross-Site Tracing (XST) — " +
                            "extração de cookies HttpOnly via scripts."),
            "PUT",     new MethodRisk("HIGH",
                    "PUT habilitado pode permitir upload de arquivos arbitrários."),
            "DELETE",  new MethodRisk("HIGH",
                    "DELETE habilitado pode permitir remoção de recursos."),
            "CONNECT", new MethodRisk("MEDIUM",
                    "CONNECT pode ser abusado para proxy tunneling."),
            "PATCH",   new MethodRisk("LOW",
                    "PATCH habilitado — verificar se requer autenticação.")
    );

    private final HttpClient client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    /**
     * Testa cada método perigoso contra a URL alvo.
     * Retorna apenas os que foram aceitos (2xx ou 4xx que não seja 405/501).
     *
     * 405 = Method Not Allowed = servidor rejeita corretamente
     * 501 = Not Implemented    = servidor rejeita corretamente
     * Qualquer outro status = método pode estar habilitado
     */
    public List<HttpMethodFinding> scan(String url) {
        List<HttpMethodFinding> findings = new ArrayList<>();

        for (Map.Entry<String, MethodRisk> entry : METHOD_RISKS.entrySet()) {
            String     method = entry.getKey();
            MethodRisk risk   = entry.getValue();

            HttpMethodFinding finding = probe(url, method, risk);
            if (finding != null) findings.add(finding);
        }

        return findings;
    }

    private HttpMethodFinding probe(String url, String method, MethodRisk risk) {
        try {
            HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(url))
                    .method(method, HttpRequest.BodyPublishers.noBody())
                    .timeout(Duration.ofSeconds(6))
                    .header("User-Agent", "CyberAuditScanner/1.0");

            HttpResponse<Void> resp = client.send(
                    builder.build(), HttpResponse.BodyHandlers.discarding());

            int status = resp.statusCode();

            // Método explicitamente rejeitado — OK
            if (status == 405 || status == 501) return null;

            // Rota não encontrada — não confirma que o método está habilitado
            if (status == 404 || status == 410) return null;

            // Redirect — não conclusivo
            if (status >= 300 && status < 400) return null;

            // Erro de servidor — não conclusivo
            if (status >= 500) return null;

            // 200, 201, 204 = aceito
            // 401, 403 = existe mas exige auth — ainda é informação relevante
            String severity = (status == 401 || status == 403)
                    ? "LOW"
                    : risk.severity();

            String riskDesc = (status == 401 || status == 403)
                    ? risk.description() + " (requer autenticação)"
                    : risk.description();

            return new HttpMethodFinding(method, status, true, severity, riskDesc);

        } catch (Exception e) {
            return null;
        }
    }

    private record MethodRisk(String severity, String description) {}
}