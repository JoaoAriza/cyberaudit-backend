package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.HttpMethodFinding;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.support.ResourceBundleMessageSource;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A sonda de controle: só reportar método perigoso quando o servidor DISCRIMINA
 * por método.
 *
 * Motivada por um falso positivo real (svninvestimentos.com.br): o app respondia
 * 200/202 a QUALQUER método — inclusive um inventado —, e o laudo dizia que PUT e
 * DELETE permitiam upload e remoção arbitrários. Um front-controller catch-all
 * responde igual a tudo; o status sozinho não prova que o método foi processado.
 *
 * As respostas de rede são de mentira: {@link HttpMethodService#send} é
 * sobrescrito, então a lógica inteira roda sem servidor. Cada resposta é
 * {@code [status]} ou {@code [status, HTML]}.
 */
class HttpMethodControlProbeTest {

    private static final int[] HTML = {200, 1};

    /** Serviço com as sondas trocadas por um mapa método → resposta. */
    private HttpMethodService com(Map<String, int[]> respostas) {
        var source = new ResourceBundleMessageSource();
        source.setBasename("messages");
        source.setDefaultEncoding("UTF-8");
        source.setFallbackToSystemLocale(false);

        return new HttpMethodService(new MessageCatalog(source)) {
            @Override
            Probe send(String url, String method) {
                int[] r = respostas.get(method);
                if (r == null) return null;
                String ct = (r.length > 1 && r[1] == 1) ? "text/html; charset=utf-8" : "application/json";
                return new Probe(r[0], ct);
            }
        };
    }

    private Optional<HttpMethodFinding> acha(List<HttpMethodFinding> fs, String metodo) {
        return fs.stream().filter(f -> f.getMethod().equals(metodo)).findFirst();
    }

    // ── Catch-all: suprime tudo ───────────────────────────────────────────────

    @Test
    @DisplayName("servidor que aceita o método inventado nao reporta PUT nem DELETE (caso svninvestimentos, 202)")
    void catchAll202SuprimeTudo() {
        var r = com(Map.of(
                HttpMethodService.CONTROL_METHOD, new int[]{202},
                "PUT", new int[]{202}, "DELETE", new int[]{202}, "TRACE", new int[]{202}));

        assertTrue(r.scan("https://svninvestimentos.com.br/").isEmpty(),
                "método inventado aceito com 202 => catch-all => nada é confiável");
    }

    @Test
    @DisplayName("catch-all que responde 200 sem HTML (edge/API) tambem é suprimido")
    void catchAll200JsonSuprime() {
        var r = com(Map.of(
                HttpMethodService.CONTROL_METHOD, new int[]{200},
                "PUT", new int[]{200}, "DELETE", new int[]{201}));

        assertTrue(r.scan("https://api.exemplo.com/").isEmpty());
    }

    @Test
    @DisplayName("catch-all que devolve a home (200 HTML) para tudo nao reporta")
    void catchAll200HtmlSuprime() {
        // Caso do mesmo site visto por outro caminho: GET/PUT/DELETE/inventado todos
        // 200 + HTML. Aqui o próprio filtro de 200+HTML já zera, mas a sonda de
        // controle é a garantia mesmo quando o status não é 200.
        var r = com(Map.of(
                HttpMethodService.CONTROL_METHOD, HTML,
                "PUT", HTML, "DELETE", HTML));

        assertTrue(r.scan("https://loja.exemplo.com/").isEmpty());
    }

    // ── Servidor que discrimina: reporta de verdade ───────────────────────────

    @Test
    @DisplayName("servidor que rejeita o inventado mas aceita PUT/DELETE reporta os dois como HIGH")
    void servidorQueDiscriminaReporta() {
        var r = com(Map.of(
                HttpMethodService.CONTROL_METHOD, new int[]{405},   // rejeita o que não conhece
                "PUT", new int[]{201}, "DELETE", new int[]{204}, "TRACE", new int[]{405}));

        List<HttpMethodFinding> fs = r.scan("https://alvo.exemplo.com/");

        assertEquals("HIGH", acha(fs, "PUT").orElseThrow().getSeverity());
        assertEquals("HIGH", acha(fs, "DELETE").orElseThrow().getSeverity());
        assertTrue(acha(fs, "TRACE").isEmpty(), "TRACE 405 é rejeição correta");
    }

    @Test
    @DisplayName("TRACE aceito num servidor que discrimina continua CRITICAL")
    void traceAceitoEhCritical() {
        var r = com(Map.of(
                HttpMethodService.CONTROL_METHOD, new int[]{501},
                "TRACE", new int[]{200}));   // 200 sem HTML = TRACE respondeu

        assertEquals("CRITICAL", acha(r.scan("https://alvo.exemplo.com/"), "TRACE").orElseThrow().getSeverity());
    }

    // ── Autenticação: não é catch-all, e rebaixa ──────────────────────────────

    @Test
    @DisplayName("inventado com 403 nao dispara a supressao: o servidor discrimina")
    void inventadoComAuthNaoSuprime() {
        // 401/403 no método inventado = o servidor não é o catch-all silencioso.
        // Se ele solta PUT sem auth, isso é achado real.
        var r = com(Map.of(
                HttpMethodService.CONTROL_METHOD, new int[]{403},
                "PUT", new int[]{200}));   // 200 sem HTML

        assertEquals("HIGH", acha(r.scan("https://alvo.exemplo.com/"), "PUT").orElseThrow().getSeverity());
    }

    @Test
    @DisplayName("PUT atrás de autenticação nao é reportado; TRACE com auth vira LOW")
    void auth() {
        var r = com(Map.of(
                HttpMethodService.CONTROL_METHOD, new int[]{405},
                "PUT", new int[]{401}, "TRACE", new int[]{403}));

        List<HttpMethodFinding> fs = r.scan("https://alvo.exemplo.com/");
        assertTrue(acha(fs, "PUT").isEmpty(), "PUT atrás de auth é API REST correta, não achado");
        assertEquals("LOW", acha(fs, "TRACE").orElseThrow().getSeverity(),
                "TRACE reflete a requisição mesmo com auth (XST), então é reportado, mas rebaixado");
    }

    // ── Robustez ──────────────────────────────────────────────────────────────

    @Test
    @DisplayName("falha de rede na sonda de controle nao esconde achado real")
    void controleFalhoNaoSuprime() {
        // Sem entrada para o método de controle => send devolve null => sem prova de
        // catch-all => segue no melhor esforço.
        var r = com(Map.of("PUT", new int[]{201}));

        assertEquals("HIGH", acha(r.scan("https://alvo.exemplo.com/"), "PUT").orElseThrow().getSeverity());
    }

    @Test
    @DisplayName("servidor bem configurado (405 em tudo) nao reporta nada")
    void servidorLimpo() {
        var respostas = new HashMap<String, int[]>();
        for (String m : List.of(HttpMethodService.CONTROL_METHOD, "PUT", "DELETE", "TRACE", "CONNECT")) {
            respostas.put(m, new int[]{405});
        }

        assertTrue(com(respostas).scan("https://seguro.exemplo.com/").isEmpty());
    }
}
