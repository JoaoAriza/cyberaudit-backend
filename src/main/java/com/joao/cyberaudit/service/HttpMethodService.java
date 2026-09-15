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
     * CONNECT também não é testado, por dois motivos que se somam:
     *   1. o {@link HttpClient} do JDK recusa CONNECT em {@code method()} com
     *      {@code IllegalArgumentException}, então a sonda sempre caía no catch e o
     *      método nunca era de fato testado — reportar risco dele era buraco
     *      silencioso no laudo;
     *   2. mesmo se desse para enviar, CONNECT contra um servidor de ORIGEM
     *      (nginx/Apache/PHP) só retorna 405/501. O risco de CONNECT é o proxy
     *      aberto, e isso se testa contra um PROXY, tentando abrir um túnel — não
     *      contra o site. É sonda separada, se um dia fizer sentido.
     *
     * O mapa guarda a CHAVE do texto, não o texto. Como é {@code static}, resolver
     * aqui congelaria o idioma no carregamento da classe — o primeiro scan decidiria
     * o idioma de todos os outros.
     */
    private static final Map<String, MethodRisk> METHOD_RISKS = Map.of(
            "TRACE",   new MethodRisk("CRITICAL", "METHOD_TRACE"),
            "PUT",     new MethodRisk("HIGH",     "METHOD_PUT"),
            "DELETE",  new MethodRisk("HIGH",     "METHOD_DELETE")
    );

    /**
     * Método de controle: um token de método que servidor nenhum implementa.
     *
     * É o coração da defesa contra falso positivo. Se o servidor "aceita" ESTE
     * método — que não existe —, ele responde igual a QUALQUER método: é um
     * front-controller catch-all (típico de PHP, que serve o index para tudo) ou um
     * edge/WAF que engole a requisição. Num servidor desses, PUT ou DELETE
     * "aceitos" não provam nada, porque um método inventado é aceito do mesmo jeito.
     *
     * Caso real que motivou (svninvestimentos.com.br): o método inventado respondia
     * 200/202 exatamente como PUT e DELETE, e o laudo reportava upload e remoção
     * arbitrários que não existiam.
     *
     * Uppercase e sem colidir com método real. Não pode ser CONNECT — o
     * {@link HttpClient} do JDK o recusa em {@code method()}, a mesma razão pela qual
     * CONNECT saiu do conjunto testado (ver {@link #METHOD_RISKS}).
     */
    static final String CONTROL_METHOD = "XCYBERAUDIT";

    private final HttpClient client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    private final MessageCatalog catalog;

    public HttpMethodService(MessageCatalog catalog) {
        this.catalog = catalog;
    }

    /**
     * Testa cada método perigoso contra a URL alvo, mas só depois de confirmar que o
     * servidor DISCRIMINA por método — ver {@link #CONTROL_METHOD}.
     *
     * Se a sonda de controle é aceita, o servidor responde uniforme a tudo e nenhum
     * achado de método é confiável: devolve lista vazia. Se a sonda de controle
     * falha na rede (null), segue no melhor esforço: só suprime quando há PROVA de
     * catch-all, nunca por um erro transitório que esconderia achado real.
     */
    public List<HttpMethodFinding> scan(String url) {
        Probe control = send(url, CONTROL_METHOD);
        if (control != null && ehCatchAll(control)) {
            return List.of();
        }

        List<HttpMethodFinding> findings = new ArrayList<>();
        for (Map.Entry<String, MethodRisk> entry : METHOD_RISKS.entrySet()) {
            HttpMethodFinding finding = classify(url, entry.getKey(), entry.getValue());
            if (finding != null) findings.add(finding);
        }
        return findings;
    }

    /**
     * O servidor aceitou um método que não existe — logo aceita qualquer um.
     *
     * "Aceitou" é o MESMO critério que marcaria um método perigoso como habilitado:
     * nem rejeição clara nem exigência de autenticação. Se o método inventado leva
     * 401/403, o servidor discrimina (ou bloqueia tudo, e aí PUT/DELETE já caem no
     * mesmo 401/403 e não são reportados) — não é o catch-all silencioso que engana.
     */
    private boolean ehCatchAll(Probe control) {
        return !rejeitado(control) && !requerAuth(control.status());
    }

    private HttpMethodFinding classify(String url, String method, MethodRisk risk) {
        Probe p = send(url, method);
        if (p == null) return null;

        // Método explicitamente rejeitado, rota inexistente, redirect ou erro: não
        // confirma nada.
        if (rejeitado(p)) return null;

        boolean requiresAuth = requerAuth(p.status());

        // PUT/DELETE atrás de autenticação = API REST bem-comportada. Só interessa
        // se acessível sem auth, ou se for TRACE (o XST vale mesmo com auth).
        if (requiresAuth && !"TRACE".equals(method)) return null;

        String severity = requiresAuth ? "LOW" : risk.severity();
        return new HttpMethodFinding(method, p.status(), true, severity,
                describeRisk(risk.descriptionKey(), requiresAuth));
    }

    /**
     * true quando o status indica que o servidor NÃO habilita o método — rejeição
     * clara ou resposta inconclusiva.
     *
     * 405/501: rejeição explícita. 404/410: rota não existe. 400: requisição
     * recusada. 3xx: redirect. 5xx: erro. 200 + HTML: o servidor devolveu a própria
     * página padrão, não processou o método.
     */
    private boolean rejeitado(Probe p) {
        int status = p.status();
        if (status == 405 || status == 501) return true;
        if (status == 404 || status == 410) return true;
        if (status == 400) return true;
        if (status >= 300 && status < 400) return true;
        if (status >= 500) return true;
        return status == 200 && p.contentType().contains("text/html");
    }

    private boolean requerAuth(int status) {
        return status == 401 || status == 403;
    }

    /** Uma resposta de sonda, reduzida ao que a decisão usa. */
    record Probe(int status, String contentType) {}

    /**
     * Manda um método contra a URL e devolve status + content-type. Null em falha de
     * rede ou método recusado pelo próprio HttpClient.
     *
     * Visível ao teste: é o único ponto de rede do serviço, e sobrescrevê-lo permite
     * exercitar toda a lógica de catch-all e classificação sem servidor real.
     */
    Probe send(String url, String method) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .method(method, HttpRequest.BodyPublishers.noBody())
                    .timeout(Duration.ofSeconds(6))
                    .header("User-Agent", ScannerHttp.USER_AGENT)
                    .build();
            HttpResponse<Void> resp = client.send(req, HttpResponse.BodyHandlers.discarding());
            String contentType = resp.headers().firstValue("content-type").orElse("").toLowerCase();
            return new Probe(resp.statusCode(), contentType);
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
