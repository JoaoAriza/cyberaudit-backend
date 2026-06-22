package com.joao.cyberaudit.service;

import com.joao.cyberaudit.exception.DomainBlockedException;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;

/**
 * Guard anti-SSRF aplicado a TODA URL de scan antes de qualquer requisição.
 *
 * Resolve o host do alvo e rejeita destinos que apontem para a infraestrutura
 * interna — loopback, link-local (inclui o endpoint de metadata da cloud
 * 169.254.169.254), redes privadas RFC 1918, CGNAT, ULA IPv6 e endereços
 * wildcard/multicast.
 *
 * Sem este guard, um visitante NÃO autenticado poderia usar o backend como
 * proxy de SSRF / port-scanner contra a rede onde o serviço roda
 * (ex.: http://169.254.169.254/latest/meta-data/, http://localhost:5434/).
 *
 * Limitação conhecida: NÃO protege contra DNS-rebinding (TOCTOU) — o host é
 * re-resolvido pelo HttpClient no momento do fetch, então um DNS malicioso
 * poderia devolver um IP público aqui e um IP interno na conexão real. O
 * fechamento completo exige fixar o IP resolvido na conexão e será tratado
 * junto do refactor do HttpFetchService.
 */
public final class SsrfGuard {

    private SsrfGuard() {}

    /**
     * Valida a URL de destino. Lança {@link DomainBlockedException} (mapeada
     * para HTTP 403 no GlobalExceptionHandler) se o host resolver para um
     * endereço interno/privado.
     *
     * @param url URL já normalizada (com esquema http/https)
     */
    public static void validate(String url) {
        String host = extractHost(url);
        if (host == null || host.isBlank()) {
            throw new DomainBlockedException("URL inválida para scan: host ausente.");
        }

        InetAddress[] addresses;
        try {
            addresses = InetAddress.getAllByName(host);
        } catch (UnknownHostException e) {
            // Host não resolve — não é um alvo interno acessível. Deixa o fluxo
            // seguir; a falha de conexão é tratada normalmente downstream
            // (UnknownHostException → 400 no GlobalExceptionHandler).
            return;
        }

        for (InetAddress addr : addresses) {
            if (isForbidden(addr)) {
                throw new DomainBlockedException(
                        "Scan bloqueado: o domínio aponta para um endereço interno/privado ("
                                + addr.getHostAddress() + "). Apenas alvos públicos são permitidos.");
            }
        }
    }

    private static boolean isForbidden(InetAddress addr) {
        if (addr.isLoopbackAddress()      // 127.0.0.0/8, ::1
                || addr.isLinkLocalAddress()  // 169.254.0.0/16 (metadata cloud), fe80::/10
                || addr.isSiteLocalAddress()  // 10/8, 172.16/12, 192.168/16
                || addr.isAnyLocalAddress()   // 0.0.0.0, ::
                || addr.isMulticastAddress()) {
            return true;
        }

        byte[] b = addr.getAddress();

        // IPv4 — faixas reservadas não cobertas pelos métodos padrão do InetAddress
        if (b.length == 4) {
            int o0 = b[0] & 0xFF, o1 = b[1] & 0xFF;
            // CGNAT 100.64.0.0/10 (RFC 6598)
            if (o0 == 100 && o1 >= 64 && o1 <= 127) return true;
        }

        // IPv6 — Unique Local Address fc00::/7 (RFC 4193).
        // isSiteLocalAddress() no Java só cobre o prefixo deprecated fec0::/10.
        if (b.length == 16 && (b[0] & 0xFE) == 0xFC) return true;

        return false;
    }

    private static String extractHost(String url) {
        try {
            String host = URI.create(url).getHost();
            if (host == null) return null;
            // URI.getHost() devolve IPv6 entre colchetes (ex.: "[::1]"); InetAddress não aceita.
            if (host.startsWith("[") && host.endsWith("]")) {
                host = host.substring(1, host.length() - 1);
            }
            return host;
        } catch (Exception e) {
            return null;
        }
    }
}
