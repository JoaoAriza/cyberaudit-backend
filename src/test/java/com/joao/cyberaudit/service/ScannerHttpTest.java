package com.joao.cyberaudit.service;

import com.joao.cyberaudit.exception.DomainBlockedException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Flow;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScannerHttpTest {

    private final HttpClient client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    // ── Validação antes de conectar ──────────────────────────────────────────

    @Test
    @DisplayName("sendFollowingSafely bloqueia a URL inicial interna sem abrir conexão")
    void bloqueiaUrlInicialInterna() {
        HttpRequest req = HttpRequest.newBuilder(URI.create("http://169.254.169.254/latest/meta-data/"))
                .GET().build();

        assertThrows(DomainBlockedException.class,
                () -> ScannerHttp.sendFollowingSafely(client, req, ScannerHttp.limitedString()));
    }

    @Test
    @DisplayName("sendFollowingSafely bloqueia loopback e redes privadas")
    void bloqueiaLoopbackEPrivadas() {
        for (String url : List.of("http://127.0.0.1:8080/", "http://192.168.0.1/", "http://[::1]/")) {
            HttpRequest req = HttpRequest.newBuilder(URI.create(url)).GET().build();
            assertThrows(DomainBlockedException.class,
                    () -> ScannerHttp.sendFollowingSafely(client, req, ScannerHttp.limitedString()),
                    "deveria bloquear " + url);
        }
    }

    // ── Corpo limitado ───────────────────────────────────────────────────────

    @Test
    @DisplayName("limitedString trunca no teto e cancela a assinatura")
    void truncaNoTeto() throws Exception {
        int limit = 64;
        var subscriber = ScannerHttp.limitedString(limit).apply(responseInfo("text/html"));

        RecordingSubscription subscription = new RecordingSubscription();
        subscriber.onSubscribe(subscription);
        // 10 KiB de corpo para um teto de 64 bytes
        subscriber.onNext(List.of(ByteBuffer.wrap("x".repeat(10_240).getBytes(StandardCharsets.UTF_8))));

        String body = subscriber.getBody().toCompletableFuture().get();
        assertEquals(limit, body.length());
        assertTrue(subscription.cancelled, "a assinatura deve ser cancelada ao atingir o teto");
    }

    @Test
    @DisplayName("limitedString entrega o corpo inteiro quando cabe no teto")
    void entregaCorpoInteiro() throws Exception {
        var subscriber = ScannerHttp.limitedString(1024).apply(responseInfo("text/html"));
        subscriber.onSubscribe(new RecordingSubscription());
        subscriber.onNext(List.of(ByteBuffer.wrap("<html>ok</html>".getBytes(StandardCharsets.UTF_8))));
        subscriber.onComplete();

        assertEquals("<html>ok</html>", subscriber.getBody().toCompletableFuture().get());
    }

    @Test
    @DisplayName("limitedString respeita o charset do Content-Type")
    void respeitaCharset() throws Exception {
        var subscriber = ScannerHttp.limitedString(1024)
                .apply(responseInfo("text/html; charset=ISO-8859-1"));
        subscriber.onSubscribe(new RecordingSubscription());
        subscriber.onNext(List.of(ByteBuffer.wrap("ação".getBytes(StandardCharsets.ISO_8859_1))));
        subscriber.onComplete();

        assertEquals("ação", subscriber.getBody().toCompletableFuture().get());
    }

    @Test
    @DisplayName("limitedString agrega múltiplos chunks até o teto")
    void agregaChunks() throws Exception {
        var subscriber = ScannerHttp.limitedString(10).apply(responseInfo("text/plain"));
        subscriber.onSubscribe(new RecordingSubscription());
        subscriber.onNext(List.of(
                ByteBuffer.wrap("abcd".getBytes(StandardCharsets.UTF_8)),
                ByteBuffer.wrap("efghijklmno".getBytes(StandardCharsets.UTF_8))));

        assertEquals("abcdefghij", subscriber.getBody().toCompletableFuture().get());
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static HttpResponse.ResponseInfo responseInfo(String contentType) {
        HttpHeaders headers = HttpHeaders.of(
                Map.of("content-type", List.of(contentType)), (k, v) -> true);
        return new HttpResponse.ResponseInfo() {
            @Override public int statusCode() { return 200; }
            @Override public HttpHeaders headers() { return headers; }
            @Override public HttpClient.Version version() { return HttpClient.Version.HTTP_1_1; }
        };
    }

    private static final class RecordingSubscription implements Flow.Subscription {
        boolean cancelled;
        @Override public void request(long n) { }
        @Override public void cancel() { cancelled = true; }
    }
}
