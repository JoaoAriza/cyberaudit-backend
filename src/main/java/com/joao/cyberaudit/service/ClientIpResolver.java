package com.joao.cyberaudit.service;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * IP real do cliente, único ponto de verdade para tudo que é limitado por IP:
 * cota diária de guest, lockout de login, rate-limit por minuto e dono de scan
 * assíncrono anônimo.
 *
 * <h2>Por que não usar só `server.forward-headers-strategy`</h2>
 *
 * Porque errar aquele enum não quebra nada de forma visível — os limites
 * simplesmente deixam de valer, em silêncio. E o valor correto depende do
 * provedor:
 *
 * <ul>
 *   <li>Proxies que <b>substituem</b> o X-Forwarded-For (nginx configurado como
 *       em deploy/, Cloudflare Tunnel) → o primeiro valor é confiável.</li>
 *   <li>Proxies que <b>apendam</b> ao header que o cliente mandou (Render, e a
 *       maioria dos PaaS) → o primeiro valor é escrito pelo ATACANTE. Quem
 *       mandasse `X-Forwarded-For: 1.2.3.4` teria scans de guest ilimitados e
 *       login sem lockout.</li>
 * </ul>
 *
 * <h2>Como este resolvedor funciona</h2>
 *
 * A lista do X-Forwarded-For cresce da esquerda para a direita: cada proxy
 * acrescenta ao final o IP de quem falou com ele. Então, contando da direita,
 * a posição {@code trustedProxyCount} é o último valor que ainda foi escrito
 * por infraestrutura nossa — tudo à esquerda disso é entrada do cliente e não
 * vale nada.
 *
 * <pre>
 *   XFF: "1.2.3.4, 203.0.113.9"          (Render, 1 proxy)
 *         ↑ forjado   ↑ escrito pelo Render  → devolve 203.0.113.9
 *
 *   XFF: "1.2.3.4, 203.0.113.9, 172.71.0.1"   (Cloudflare → Render, 2 proxies)
 *         ↑ forjado   ↑ real       ↑ borda CF  → devolve 203.0.113.9
 * </pre>
 *
 * Se a cadeia vier mais curta que o esperado, cai para {@code getRemoteAddr()}
 * em vez de adivinhar: o pior caso vira todo mundo no mesmo balde (limite
 * apertado demais), nunca alguém escapando do balde.
 */
@Service
public class ClientIpResolver {

    private static final String XFF_HEADER = "X-Forwarded-For";

    /**
     * Quantos proxies confiáveis existem entre o cliente e a aplicação.
     * 0 = app exposto direto (ignora o header por completo).
     * 1 = Render, ou nginx/Tunnel próprio.
     * 2 = Cloudflare proxiando na frente de um dos anteriores.
     */
    private final int trustedProxyCount;

    public ClientIpResolver(@Value("${app.trusted-proxy-count:0}") int trustedProxyCount) {
        this.trustedProxyCount = Math.max(0, trustedProxyCount);
    }

    public String resolve(HttpServletRequest request) {
        if (request == null) return "desconhecido";

        String direct = request.getRemoteAddr();
        if (trustedProxyCount == 0) return normalize(direct);

        String header = request.getHeader(XFF_HEADER);
        if (header == null || header.isBlank()) return normalize(direct);

        String[] hops = header.split(",");
        // Índice contado a partir da direita: o valor escrito pelo proxy mais
        // externo que ainda é nosso.
        int index = hops.length - trustedProxyCount;
        if (index < 0) {
            // Menos saltos que o configurado: a requisição não veio pela cadeia
            // esperada. Não dá para saber qual entrada é confiável — usa o peer.
            return normalize(direct);
        }

        String candidate = hops[index].trim();
        return candidate.isEmpty() ? normalize(direct) : normalize(candidate);
    }

    /**
     * Tira porta e colchetes que alguns proxies acrescentam ("1.2.3.4:53812",
     * "[2001:db8::1]:443"). Sem isso o mesmo cliente contaria como vários IPs
     * distintos, já que a porta muda a cada conexão — e o rate-limit não pegaria.
     */
    private String normalize(String ip) {
        if (ip == null || ip.isBlank()) return "desconhecido";
        String value = ip.trim();

        if (value.startsWith("[")) {                       // [IPv6]:porta
            int close = value.indexOf(']');
            return close > 0 ? value.substring(1, close) : value;
        }
        int colon = value.indexOf(':');
        if (colon > 0 && value.indexOf(':', colon + 1) < 0) {
            return value.substring(0, colon);              // IPv4:porta
        }
        return value;                                       // IPv6 puro ou IPv4
    }
}
