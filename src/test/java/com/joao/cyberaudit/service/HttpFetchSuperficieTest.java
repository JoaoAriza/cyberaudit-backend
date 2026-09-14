package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.FormSurfaceResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLSession;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * So resposta 2xx e a pagina.
 *
 * O caso que motivou: petz.com.br/checkout/login respondeu 403 ao scanner. O corpo
 * de um bloqueio e o do bloqueio — as vezes um captcha com campo —, e ler os campos
 * dele diria o que o WAF coleta, nao o que a pagina coleta.
 */
class HttpFetchSuperficieTest {

    private final HttpFetchService service = new HttpFetchService(new FormSurfaceService());

    private static final String CAPTCHA =
            "<form action=\"/challenge\"><input type=\"email\" name=\"email\"><input type=\"password\"></form>";

    private HttpResponse<String> resposta(int status, String corpo) {
        URI uri = URI.create("https://loja.test/checkout/login");
        return new HttpResponse<>() {
            @Override public int statusCode() { return status; }
            @Override public HttpRequest request() { return HttpRequest.newBuilder(uri).build(); }
            @Override public Optional<HttpResponse<String>> previousResponse() { return Optional.empty(); }
            @Override public HttpHeaders headers() { return HttpHeaders.of(Map.of(), (k, v) -> true); }
            @Override public String body() { return corpo; }
            @Override public Optional<SSLSession> sslSession() { return Optional.empty(); }
            @Override public URI uri() { return uri; }
            @Override public HttpClient.Version version() { return HttpClient.Version.HTTP_1_1; }
        };
    }

    @Test
    @DisplayName("resposta 200 tem os campos lidos")
    void respostaOkELida() {
        FormSurfaceResult f = service.buildResult(resposta(200, CAPTCHA)).getFormSurface();
        assertTrue(f.isAnalyzed());
        assertTrue(f.isHasPasswordField());
    }

    @Test
    @DisplayName("links sugeridos sao resolvidos pela URL final da resposta")
    void linksPelaUrlFinal() {
        FormSurfaceResult f = service.buildResult(resposta(200, "<a href=\"/minha-conta\">Conta</a>")).getFormSurface();
        assertEquals("https://loja.test/minha-conta", f.getLinkedAreas().get(0).getUrl());
    }

    @Test
    @DisplayName("resposta 403 nao tem os campos lidos, mesmo com formulario no corpo")
    void bloqueioNaoELido() {
        FormSurfaceResult f = service.buildResult(resposta(403, CAPTCHA)).getFormSurface();
        assertFalse(f.isAnalyzed(), "o corpo do 403 e o do bloqueio, nao o da pagina");
        assertFalse(f.isHasPasswordField());
        assertFalse(f.isCollectsPii());
    }
}
