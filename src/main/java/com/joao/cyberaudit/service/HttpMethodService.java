package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.HttpMethodFinding;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

@Service
public class HttpMethodService {

    /**
     * Métodos a testar com seus riscos.
     * GET, POST, HEAD são normais — não testados. OPTIONS é coberto pelo CORS probe.
     * PATCH não é testado: é método REST padrão (RFC 5789), não vulnerabilidade.
     *
     * O mapa guarda a CHAVE do texto, não o texto. Como é {@code static}, resolver
     * aqui congelaria o idioma no carregamento da classe — o primeiro scan decidiria
     * o idioma de todos os outros.
     */
    private static final Map<String, MethodRisk> METHOD_RISKS = Map.of(
            "TRACE",   new MethodRisk("CRITICAL", "METHOD_TRACE"),
            "PUT",     new MethodRisk("HIGH",     "METHOD_PUT"),
            "DELETE",  new MethodRisk("HIGH",     "METHOD_DELETE"),
            "CONNECT", new MethodRisk("MEDIUM",   "METHOD_CONNECT")
    );

    private final HttpClient client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    private final MessageCatalog catalog;

    public HttpMethodService(MessageCatalog catalog) {
        this.catalog = catalog;
    }

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
                    .header("User-Agent", ScannerHttp.USER_AGENT);

            HttpResponse<Void> resp = client.send(
                    builder.build(), HttpResponse.BodyHandlers.discarding());
            int status = resp.statusCode();

            // Método explicitamente rejeitado — OK
            if (status == 405 || status == 501) return null;

            // Rota não encontrada — não confirma método habilitado
            if (status == 404 || status == 410) return null;

            // Bad Request — servidor rejeitou, não confirma método habilitado
            if (status == 400) return null;

            // Redirect — não conclusivo
            if (status >= 300 && status < 400) return null;

            // Erro de servidor — não conclusivo
            if (status >= 500) return null;

            if (status == 200) {
                String contentType = resp.headers()
                        .firstValue("content-type").orElse("").toLowerCase();
                // 200 + HTML = site retornou sua página padrão, não processou o método
                if (contentType.contains("text/html")) return null;
            }

            boolean requiresAuth = (status == 401 || status == 403);

            // PUT/DELETE com autenticação = comportamento correto de API REST.
            // Só é relevante se acessível sem auth (200/204) ou com auth mas TRACE (sempre perigoso).
            if (requiresAuth && !"TRACE".equals(method)) return null;

            String severity = requiresAuth ? "LOW" : risk.severity();

            return new HttpMethodFinding(method, status, true, severity,
                    describeRisk(risk.descriptionKey(), requiresAuth));

        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Visível ao teste: é o texto que vai para o card, e a chave dele é montada
     * fora do alcance do compilador.
     *
     * A ressalva de autenticação envolve a frase inteira em vez de ser colada nela.
     * Compor aqui é seguro — a frase já está fechada, e o parêntese vem do mesmo
     * catálogo, no mesmo idioma. O que não se pode é enfiar fragmento traduzido no
     * MEIO de outra frase, como o rótulo de tipo fazia no resumo do WAF.
     */
    String describeRisk(String descriptionKey, boolean requiresAuth) {
        String texto = catalog.desc(descriptionKey);
        return requiresAuth ? catalog.desc("METHOD_REQUIRES_AUTH", texto) : texto;
    }

    /** Visível ao teste: método novo sem tradução é buraco silencioso no laudo. */
    static Collection<String> chavesDeRisco() {
        return METHOD_RISKS.values().stream().map(MethodRisk::descriptionKey).toList();
    }

    private record MethodRisk(String severity, String descriptionKey) {}
}