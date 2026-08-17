package com.joao.cyberaudit.service;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.concurrent.atomic.AtomicBoolean;

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
 *
 * <h2>Por que o CF-Connecting-IP vem antes de tudo</h2>
 *
 * Contar saltos é frágil justamente onde mais importa: o Render serve por trás
 * do Cloudflare <i>deles</i> e ainda acrescenta um load balancer interno, então
 * a cadeia real é mais longa do que "Render = 1 proxy" sugere. Com a contagem
 * errada o app passou a resolver o IP interno do balanceador (10.x), que muda a
 * cada requisição — quebrando dono de scan assíncrono, cota de guest e lockout,
 * todos em silêncio.
 *
 * O Cloudflare <b>sobrescreve</b> {@code CF-Connecting-IP} com o IP de quem
 * abriu a conexão, então ele não é forjável por trás dele e não depende de
 * quantos saltos existem depois. Por isso: se estamos declaradamente atrás de
 * proxy ({@code trustedProxyCount > 0}) e o header veio, ele ganha. Fora daí,
 * nada muda — a contagem continua valendo para nginx/Tunnel próprios.
 */
@Service
public class ClientIpResolver {

    private static final String XFF_HEADER = "X-Forwarded-For";

    /**
     * Escrito pelo Cloudflare (o do Render inclusive) com o IP real do cliente.
     * Só é considerado quando já assumimos que há proxy na frente — se o app
     * estiver exposto direto, qualquer um poderia mandar este header.
     */
    private static final String CF_HEADER = "CF-Connecting-IP";

    private static final Logger log = LoggerFactory.getLogger(ClientIpResolver.class);

    /** O aviso de configuração vale uma vez; por requisição viraria ruído. */
    private final AtomicBoolean avisouIpPrivado = new AtomicBoolean(false);

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
        String ip = resolveRaw(request);
        alertaSeParecerMaConfiguracao(ip);
        return ip;
    }

    private String resolveRaw(HttpServletRequest request) {
        if (request == null) return "desconhecido";

        String direct = request.getRemoteAddr();
        if (trustedProxyCount == 0) return normalize(direct);

        // Atrás de proxy declarado, o Cloudflare é a fonte mais confiável: ele
        // sobrescreve este header e o valor não depende do tamanho da cadeia.
        String cf = request.getHeader(CF_HEADER);
        if (cf != null && !cf.isBlank() && cf.indexOf(',') < 0) {
            // Uma vírgula aqui significaria header acumulado — não é o que o
            // Cloudflare produz, então nesse caso é entrada de cliente: descarta.
            return normalize(cf);
        }

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
     * Um IP privado como "cliente" enquanto há proxy configurado significa que a
     * cadeia não é a esperada — foi assim que a produção passou a contar todo
     * mundo pelo balanceador interno do Render. Sem este aviso o sintoma só
     * aparece muito depois, como scan de guest sumindo e cota sem efeito.
     */
    private void alertaSeParecerMaConfiguracao(String ip) {
        if (trustedProxyCount == 0 || !isPrivado(ip)) return;
        if (!avisouIpPrivado.compareAndSet(false, true)) return;

        log.warn("""
                IP de cliente resolvido como endereço privado ({}) com \
                app.trusted-proxy-count={}. Tudo que é limitado por IP (cota de \
                guest, rate-limit, lockout de login, dono de scan anônimo) está \
                caindo no mesmo balde. Confira se o proxy envia CF-Connecting-IP \
                ou ajuste TRUSTED_PROXY_COUNT para o tamanho real da cadeia.""",
                ip, trustedProxyCount);
    }

    /** Faixas RFC1918/loopback/link-local — nunca são um cliente da internet. */
    private boolean isPrivado(String ip) {
        if (ip == null || ip.isBlank() || "desconhecido".equals(ip)) return false;
        String v = ip.toLowerCase();

        if (v.startsWith("10.") || v.startsWith("192.168.")
                || v.startsWith("127.") || v.startsWith("169.254.")) return true;
        if (v.startsWith("172.")) {
            int dot = v.indexOf('.', 4);
            if (dot > 4) {
                try {
                    int segundo = Integer.parseInt(v.substring(4, dot));
                    if (segundo >= 16 && segundo <= 31) return true;
                } catch (NumberFormatException ignored) {
                    // Não é IPv4 numérico — deixa passar como público.
                }
            }
        }
        // IPv6: loopback e unique-local (fc00::/7).
        return v.equals("::1") || v.startsWith("fc") || v.startsWith("fd");
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
