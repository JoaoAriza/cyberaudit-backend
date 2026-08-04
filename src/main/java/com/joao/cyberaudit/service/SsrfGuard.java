package com.joao.cyberaudit.service;

import com.joao.cyberaudit.exception.DomainBlockedException;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.Locale;
import java.util.Set;

/**
 * Guard anti-SSRF aplicado a toda URL de scan antes de qualquer requisição —
 * na URL de entrada e novamente a cada hop de redirect (ver {@link ScannerHttp}).
 *
 * Rejeita esquemas fora de http/https, URLs com userinfo e destinos internos:
 * loopback, link-local (inclui metadata cloud 169.254.169.254), redes privadas
 * RFC 1918, CGNAT, faixas reservadas IANA, ULA IPv6, wildcard e multicast.
 * Também desembrulha IPv4 embutido em IPv6 (mapped, 6to4, NAT64), usado para
 * mascarar alvos internos atrás de um endereço v6 aparentemente público.
 *
 * DNS rebinding: a janela entre validação e conexão é reduzida pelo cache de DNS
 * positivo da JVM (networkaddress.cache.ttl, ver DnsCacheConfig) — o endereço
 * validado aqui é o mesmo que o HttpClient usa dentro do TTL.
 */
public final class SsrfGuard {

    private SsrfGuard() {}

    private static final Set<String> ALLOWED_SCHEMES = Set.of("http", "https");

    /**
     * Nomes que nunca devem ser alvo, mesmo que a resolução falhe ou aponte para
     * fora. Defesa em profundidade — a checagem por IP resolvido é a principal.
     */
    private static final Set<String> BLOCKED_SUFFIXES = Set.of(
            "localhost", ".localhost", ".local", ".internal", ".home.arpa");

    /**
     * Valida a URL de destino. Lança {@link DomainBlockedException} (mapeada
     * para HTTP 403 no GlobalExceptionHandler) se o esquema não for http/https
     * ou se o host resolver para um endereço interno/privado.
     *
     * @param url URL já normalizada (com esquema http/https)
     */
    public static void validate(String url) {
        URI uri = parse(url);
        validateScheme(uri);

        if (uri.getUserInfo() != null) {
            // https://alvo-confiavel@169.254.169.254/ — o userinfo esconde o host real
            // de qualquer validação feita por string. Nenhum scan legítimo precisa disso.
            throw new DomainBlockedException("URL inválida para scan: credenciais na URL não são permitidas.");
        }

        String host = extractHost(uri);
        if (host == null || host.isBlank()) {
            throw new DomainBlockedException("URL inválida para scan: host ausente.");
        }
        validateHost(host);
    }

    /**
     * Valida um host isolado (sem URL) — usado por endpoints que recebem só o
     * domínio, como a verificação de posse.
     */
    public static void validateHost(String host) {
        if (host == null || host.isBlank()) {
            throw new DomainBlockedException("Host inválido para scan: host ausente.");
        }

        String normalized = host.toLowerCase(Locale.ROOT);
        if (normalized.endsWith(".")) normalized = normalized.substring(0, normalized.length() - 1);
        for (String suffix : BLOCKED_SUFFIXES) {
            if (normalized.equals(suffix) || normalized.endsWith(suffix)) {
                throw new DomainBlockedException(
                        "Scan bloqueado: '" + host + "' é um nome de rede interna. "
                                + "Apenas alvos públicos são permitidos.");
            }
        }

        InetAddress[] addresses;
        try {
            addresses = InetAddress.getAllByName(normalized);
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

    /** true se a URL é aceitável — versão não-lançante, para filtrar candidatos. */
    public static boolean isAllowed(String url) {
        try {
            validate(url);
            return true;
        } catch (DomainBlockedException e) {
            return false;
        }
    }

    /**
     * true se o endereço pertence a uma faixa que o scanner nunca deve alcançar.
     * Público para reuso na validação por hop de redirect.
     */
    public static boolean isForbidden(InetAddress addr) {
        if (addr == null) return true;

        if (addr.isLoopbackAddress()      // 127.0.0.0/8, ::1
                || addr.isLinkLocalAddress()  // 169.254.0.0/16 (metadata cloud), fe80::/10
                || addr.isSiteLocalAddress()  // 10/8, 172.16/12, 192.168/16
                || addr.isAnyLocalAddress()   // 0.0.0.0, ::
                || addr.isMulticastAddress()) {
            return true;
        }

        byte[] b = addr.getAddress();

        // IPv6 — desembrulha IPv4 embutido antes de qualquer outra checagem v6.
        if (b.length == 16) {
            byte[] embedded = extractEmbeddedIpv4(b);
            if (embedded != null) return isForbiddenIpv4(embedded);

            // Unique Local Address fc00::/7 (RFC 4193). isSiteLocalAddress() no Java
            // só cobre o prefixo deprecated fec0::/10.
            if ((b[0] & 0xFE) == 0xFC) return true;

            return false;
        }

        return b.length == 4 && isForbiddenIpv4(b);
    }

    /** Faixas IPv4 reservadas não cobertas pelos métodos padrão do InetAddress. */
    private static boolean isForbiddenIpv4(byte[] b) {
        int o0 = b[0] & 0xFF, o1 = b[1] & 0xFF, o2 = b[2] & 0xFF;

        if (o0 == 0)   return true;                       // 0.0.0.0/8 "this network"
        if (o0 == 127) return true;                       // loopback (v4 embutido em v6)
        if (o0 == 10)  return true;                       // RFC 1918
        if (o0 == 172 && o1 >= 16 && o1 <= 31) return true;
        if (o0 == 192 && o1 == 168) return true;
        if (o0 == 169 && o1 == 254) return true;          // link-local / metadata cloud
        if (o0 == 100 && o1 >= 64 && o1 <= 127) return true;  // CGNAT 100.64/10 (RFC 6598)
        if (o0 == 192 && o1 == 0 && o2 == 0) return true;     // 192.0.0.0/24 IETF
        if (o0 == 192 && o1 == 0 && o2 == 2) return true;     // TEST-NET-1
        if (o0 == 198 && (o1 == 18 || o1 == 19)) return true; // 198.18/15 benchmark
        if (o0 == 198 && o1 == 51 && o2 == 100) return true;  // TEST-NET-2
        if (o0 == 203 && o1 == 0 && o2 == 113) return true;   // TEST-NET-3
        if (o0 >= 224) return true;                       // multicast 224/4 + reservado 240/4 + broadcast

        return false;
    }

    /**
     * Extrai o IPv4 embutido em um endereço IPv6, quando houver. Cobre os formatos
     * usados para alcançar um alvo v4 interno por um literal v6: mapped
     * (::ffff:a.b.c.d), compatible (::a.b.c.d), NAT64 (64:ff9b::/96) e 6to4
     * (2002:a.b.c.d::). Devolve null se não houver IPv4 embutido.
     */
    private static byte[] extractEmbeddedIpv4(byte[] b) {
        boolean first10Zero = true;
        for (int i = 0; i < 10; i++) {
            if (b[i] != 0) { first10Zero = false; break; }
        }
        // ::ffff:a.b.c.d (mapped) e ::a.b.c.d (compatible, deprecated)
        if (first10Zero
                && ((b[10] == (byte) 0xFF && b[11] == (byte) 0xFF) || (b[10] == 0 && b[11] == 0))) {
            return new byte[]{b[12], b[13], b[14], b[15]};
        }
        // NAT64 well-known prefix 64:ff9b::/96
        if (b[0] == 0x00 && b[1] == 0x64 && b[2] == (byte) 0xFF && b[3] == (byte) 0x9B) {
            boolean middleZero = true;
            for (int i = 4; i < 12; i++) {
                if (b[i] != 0) { middleZero = false; break; }
            }
            if (middleZero) return new byte[]{b[12], b[13], b[14], b[15]};
        }
        // 6to4 2002::/16 — o IPv4 fica nos bytes 2..5
        if (b[0] == 0x20 && b[1] == 0x02) {
            return new byte[]{b[2], b[3], b[4], b[5]};
        }
        return null;
    }

    private static void validateScheme(URI uri) {
        String scheme = uri.getScheme();
        if (scheme == null || !ALLOWED_SCHEMES.contains(scheme.toLowerCase(Locale.ROOT))) {
            throw new DomainBlockedException(
                    "Esquema não permitido para scan: '" + (scheme == null ? "(ausente)" : scheme)
                            + "'. Apenas http e https são aceitos.");
        }
    }

    private static URI parse(String url) {
        if (url == null || url.isBlank()) {
            throw new DomainBlockedException("URL inválida para scan: vazia.");
        }
        try {
            return new URI(url.trim());
        } catch (Exception e) {
            throw new DomainBlockedException("URL inválida para scan: " + url);
        }
    }

    private static String extractHost(URI uri) {
        String host = uri.getHost();
        if (host == null) {
            // URI.getHost() devolve null para autoridades que o RFC 2396 rejeita
            // (ex.: underscore no host). Cai para a authority sem userinfo/porta,
            // para não deixar passar sem validação.
            String authority = uri.getAuthority();
            if (authority == null) return null;
            int at = authority.lastIndexOf('@');
            if (at >= 0) authority = authority.substring(at + 1);
            int colon = authority.lastIndexOf(':');
            if (colon >= 0 && authority.indexOf(':') == colon) authority = authority.substring(0, colon);
            host = authority;
        }
        // URI.getHost() devolve IPv6 entre colchetes (ex.: "[::1]"); InetAddress não aceita.
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }
        return host;
    }
}
