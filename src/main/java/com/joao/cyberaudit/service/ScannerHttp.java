package com.joao.cyberaudit.service;

import com.joao.cyberaudit.exception.DomainBlockedException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Flow;

/**
 * Constantes e utilitários HTTP compartilhados pelos módulos de scan.
 *
 * Além do User-Agent, concentra as duas defesas que precisam valer para TODA
 * requisição de saída do scanner:
 *
 * <ul>
 *   <li>{@link #sendFollowingSafely} — segue redirects manualmente revalidando
 *       cada hop no {@link SsrfGuard}. Deixar o HttpClient seguir sozinho
 *       (Redirect.ALWAYS/NORMAL) permite que o alvo responda 302 para
 *       169.254.169.254 e transforme o scanner em proxy para a rede interna.</li>
 *   <li>{@link #limitedString} — corpo com teto de bytes. BodyHandlers.ofString()
 *       lê a resposta inteira em memória: um alvo hostil respondendo alguns GB
 *       derruba o processo.</li>
 * </ul>
 */
public final class ScannerHttp {

    private ScannerHttp() {}

    /**
     * User-Agent único usado por todos os probes. Formato de bot transparente
     * ("compatible; ...") — passa filtros que exigem prefixo Mozilla e continua
     * identificando o scanner nos logs do site auditado.
     */
    public static final String USER_AGENT = "Mozilla/5.0 (compatible; CyberAuditScanner/1.0)";

    /** Teto padrão de corpo lido por resposta (3 MiB) — suficiente para HTML/JS de análise. */
    public static final int MAX_BODY_BYTES = 3 * 1024 * 1024;

    /**
     * Teto para respostas JSON de APIs externas (CT logs, NVD) que são desserializadas
     * inteiras: truncar quebraria o parse, então o limite é maior — mas ainda existe,
     * porque um upstream comprometido não pode derrubar o processo.
     */
    public static final int MAX_JSON_BODY_BYTES = 16 * 1024 * 1024;

    /** Máximo de redirects seguidos manualmente antes de desistir. */
    public static final int MAX_REDIRECTS = 5;

    /** Timeout de conexão padrão dos probes. */
    public static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(5);

    /** Headers atrelados à conexão/origem atual — não devem atravessar um redirect. */
    private static final Set<String> HOP_LOCAL_HEADERS = Set.of(
            "host", "connection", "content-length", "authorization", "cookie", "origin", "referer");

    // ── Redirects revalidados ────────────────────────────────────────────────

    /**
     * Envia a requisição seguindo redirects manualmente, validando a URL inicial
     * e cada destino de Location no {@link SsrfGuard}.
     *
     * O {@code client} DEVE estar configurado com {@link HttpClient.Redirect#NEVER} —
     * caso contrário o próprio cliente segue os redirects antes desta checagem.
     *
     * @throws DomainBlockedException se a URL inicial ou qualquer hop apontar para
     *                                destino interno/privado ou esquema não permitido
     */
    public static <T> HttpResponse<T> sendFollowingSafely(
            HttpClient client, HttpRequest request, HttpResponse.BodyHandler<T> handler)
            throws IOException, InterruptedException {

        SsrfGuard.validate(request.uri().toString());

        HttpRequest current = request;
        HttpResponse<T> response = client.send(current, handler);

        for (int hop = 0; hop < MAX_REDIRECTS; hop++) {
            URI next = redirectTarget(response, current.uri());
            if (next == null) return response;

            // Revalida ANTES de conectar: é aqui que o 302 → 169.254.169.254 morre.
            SsrfGuard.validate(next.toString());

            current  = rebuildFor(current, next, response.statusCode());
            response = client.send(current, handler);
        }
        // Excedeu o limite de hops — devolve a última resposta (o chamador vê o 3xx).
        return response;
    }

    /** Destino do redirect, ou null se a resposta não for um redirect utilizável. */
    private static URI redirectTarget(HttpResponse<?> response, URI base) {
        int status = response.statusCode();
        if (status != 301 && status != 302 && status != 303
                && status != 307 && status != 308) {
            return null;
        }
        Optional<String> location = response.headers().firstValue("location");
        if (location.isEmpty() || location.get().isBlank()) return null;

        try {
            String raw = location.get().trim();
            // Location relativo a protocolo ("//host/path") herda o esquema da base.
            URI target = raw.startsWith("//")
                    ? URI.create(base.getScheme() + ":" + raw)
                    : base.resolve(raw);
            return target.isAbsolute() ? target : null;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Reconstrói a requisição para o próximo hop preservando headers e timeout.
     * 307/308 mantêm método e corpo; 301/302/303 viram GET, como manda o RFC 9110.
     */
    private static HttpRequest rebuildFor(HttpRequest previous, URI target, int status) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(target);
        previous.timeout().ifPresent(builder::timeout);
        previous.headers().map().forEach((name, values) -> {
            // Host é liberado globalmente (allowRestrictedHeaders, para o probe de Host
            // Header Injection): não pode vazar para o host do próximo hop.
            if (HOP_LOCAL_HEADERS.contains(name.toLowerCase(Locale.ROOT))) return;
            for (String value : values) {
                try {
                    builder.header(name, value);
                } catch (IllegalArgumentException ignored) {
                    // header restrito pelo HttpClient (Host, Connection, ...) — não repassa
                }
            }
        });

        if (status == 307 || status == 308) {
            builder.method(previous.method(),
                    previous.bodyPublisher().orElse(HttpRequest.BodyPublishers.noBody()));
        } else {
            builder.GET();
        }
        return builder.build();
    }

    // ── Corpo limitado ───────────────────────────────────────────────────────

    /** BodyHandler de String com o teto padrão ({@link #MAX_BODY_BYTES}). */
    public static HttpResponse.BodyHandler<String> limitedString() {
        return limitedString(MAX_BODY_BYTES);
    }

    /**
     * BodyHandler de String que para de ler após {@code maxBytes} e cancela a
     * assinatura. O corpo devolvido vem truncado — os módulos analisam padrões no
     * início da resposta, então truncar é preferível a estourar a heap.
     */
    public static HttpResponse.BodyHandler<String> limitedString(int maxBytes) {
        return info -> new LimitedStringSubscriber(maxBytes, charsetOf(info));
    }

    /** Charset do Content-Type, com fallback UTF-8 — mesmo critério do BodyHandlers.ofString(). */
    private static Charset charsetOf(HttpResponse.ResponseInfo info) {
        try {
            String contentType = info.headers().firstValue("content-type").orElse("");
            int idx = contentType.toLowerCase(Locale.ROOT).indexOf("charset=");
            if (idx < 0) return StandardCharsets.UTF_8;
            String value = contentType.substring(idx + "charset=".length()).trim();
            int end = value.indexOf(';');
            if (end >= 0) value = value.substring(0, end);
            value = value.replace("\"", "").trim();
            return value.isEmpty() ? StandardCharsets.UTF_8 : Charset.forName(value);
        } catch (Exception e) {
            return StandardCharsets.UTF_8;
        }
    }

    /**
     * Acumula o corpo até o teto e cancela a assinatura ao atingi-lo — a conexão
     * é liberada sem drenar o resto da resposta.
     */
    private static final class LimitedStringSubscriber implements HttpResponse.BodySubscriber<String> {

        private final CompletableFuture<String> result = new CompletableFuture<>();
        private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        private final int maxBytes;
        private final Charset charset;

        private Flow.Subscription subscription;
        private int received;

        LimitedStringSubscriber(int maxBytes, Charset charset) {
            this.maxBytes = maxBytes;
            this.charset  = charset;
        }

        @Override
        public CompletionStage<String> getBody() {
            return result;
        }

        @Override
        public void onSubscribe(Flow.Subscription subscription) {
            this.subscription = subscription;
            subscription.request(Long.MAX_VALUE);
        }

        @Override
        public void onNext(List<ByteBuffer> items) {
            for (ByteBuffer item : items) {
                int room = maxBytes - received;
                if (room <= 0) break;
                int take = Math.min(item.remaining(), room);
                byte[] chunk = new byte[take];
                item.get(chunk);
                buffer.write(chunk, 0, take);
                received += take;
            }
            if (received >= maxBytes) {
                subscription.cancel();
                complete();
            }
        }

        @Override
        public void onError(Throwable throwable) {
            result.completeExceptionally(throwable);
        }

        @Override
        public void onComplete() {
            complete();
        }

        private void complete() {
            // complete() é idempotente: onComplete pode chegar depois do cancel.
            result.complete(buffer.toString(charset));
        }
    }
}
