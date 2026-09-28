package com.joao.cyberaudit.service;

import java.net.InetAddress;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Registro de hosts já validados pelo {@link SsrfGuard}, consultado pelo
 * {@link SsrfPinningResolverProvider} para fechar o TOCTOU de DNS rebinding.
 *
 * O problema: {@code SsrfGuard.validateHost} resolve e valida o host, mas quem
 * conecta de fato é o {@code HttpClient}, que resolve o MESMO host de novo,
 * de forma independente — e essa segunda resolução pode acontecer numa thread
 * interna do cliente, não na que chamou o guard. Um alvo com TTL de DNS baixo
 * pode responder IP público na 1ª consulta e 169.254.169.254 na 2ª.
 *
 * A correlação aqui é por HOSTNAME, não por thread: {@link SsrfGuard} grava os
 * endereços exatos que validou; {@link SsrfPinningResolverProvider} devolve
 * esses MESMOS objetos {@link InetAddress} para qualquer resolução seguinte do
 * mesmo host, esteja ela em qual thread estiver. A conexão fica garantidamente
 * presa ao endereço já auditado — não a uma nova consulta DNS.
 *
 * Hosts nunca submetidos ao guard (banco de dados, SMTP, Mercado Pago, APIs
 * externas de compliance/CT) nunca aparecem aqui e resolvem normalmente pelo
 * resolver padrão da JVM — o pinning é opt-in por chamada ao guard, não uma
 * política global de rede.
 */
final class ScanDnsPinRegistry {

    private ScanDnsPinRegistry() {}

    /**
     * Cobre confortavelmente uma validação inicial + até {@link ScannerHttp#MAX_REDIRECTS}
     * hops, sem manter pins de scans antigos por muito tempo além do necessário.
     */
    private static final long PIN_TTL_NANOS = TimeUnit.SECONDS.toNanos(60);

    private record Entry(List<InetAddress> addresses, long expiresAtNanos) {}

    private static final Map<String, Entry> PINS = new ConcurrentHashMap<>();

    /** Grava os endereços já validados pelo {@link SsrfGuard} para este host. */
    static void pin(String host, List<InetAddress> addresses) {
        PINS.put(normalize(host), new Entry(List.copyOf(addresses), System.nanoTime() + PIN_TTL_NANOS));
    }

    /** Endereços pinados para o host, ou {@code null} se não houver pin vivo. */
    static List<InetAddress> get(String host) {
        String key = normalize(host);
        Entry entry = PINS.get(key);
        if (entry == null) return null;
        if (System.nanoTime() > entry.expiresAtNanos()) {
            PINS.remove(key, entry);
            return null;
        }
        return entry.addresses();
    }

    /** Mesma normalização usada em {@link SsrfGuard#validateHost}, para as chaves baterem. */
    private static String normalize(String host) {
        String h = host.toLowerCase(Locale.ROOT);
        return h.endsWith(".") ? h.substring(0, h.length() - 1) : h;
    }
}
