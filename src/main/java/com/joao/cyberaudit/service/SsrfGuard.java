package com.joao.cyberaudit.service;

import com.joao.cyberaudit.exception.DomainBlockedException;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

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
 * DNS rebinding: os endereços validados aqui são fixados em {@link ScanDnsPinRegistry}
 * e devolvidos por {@link SsrfPinningResolverProvider} a qualquer resolução seguinte
 * do mesmo host — inclusive a que o {@code HttpClient} faz internamente ao conectar,
 * em outra thread. Não há uma segunda consulta DNS cujo resultado poderia divergir:
 * a conexão usa exatamente o {@link InetAddress} já auditado.
 */
public final class SsrfGuard {

    private SsrfGuard() {}

    private static final Set<String> ALLOWED_SCHEMES = Set.of("http", "https");

    /**
     * Hostnames liberados da checagem de IP interno/privado — vazio em produção,
     * sempre. Só é populado por {@link SsrfTestAllowlistConfig}, um bean que
     * carrega exclusivamente sob o profile Spring {@code qa-docker} (usado pelo
     * ambiente Docker do `cyberaudit-qa`, onde os alvos de teste — Juice Shop,
     * WireMock — vivem na rede privada do Docker e seriam bloqueados por
     * definição). Fora desse profile o bean nunca é instanciado, então este campo
     * nunca sai de {@code Set.of()} — não é um "if profile == X" escrito à mão,
     * é o `@Profile` do próprio Spring decidindo se a classe chega a carregar.
     */
    private static volatile Set<String> testAllowlist = Set.of();

    /** Só chamado por SsrfTestAllowlistConfig — não usar em nenhum outro lugar. */
    static void setTestAllowlist(Set<String> hosts) {
        testAllowlist = hosts == null ? Set.of() : hosts;
    }

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

        String bare = stripPort(host.trim());
        if (bare.isBlank()) {
            throw new DomainBlockedException("Host inválido para scan: host ausente.");
        }

        String normalized = bare.toLowerCase(Locale.ROOT);
        if (normalized.endsWith(".")) normalized = normalized.substring(0, normalized.length() - 1);
        for (String suffix : BLOCKED_SUFFIXES) {
            if (normalized.equals(suffix) || normalized.endsWith(suffix)) {
                throw new DomainBlockedException(
                        "Scan bloqueado: '" + host + "' é um nome de rede interna. "
                                + "Apenas alvos públicos são permitidos.");
            }
        }

        rejectNonCanonicalIpv4(normalized, host);

        InetAddress[] addresses;
        try {
            addresses = InetAddress.getAllByName(normalized);
        } catch (UnknownHostException e) {
            // Host não resolve — não é um alvo interno acessível. Deixa o fluxo
            // seguir; a falha de conexão é tratada normalmente downstream
            // (UnknownHostException → 400 no GlobalExceptionHandler).
            return;
        }

        if (!testAllowlist.contains(normalized)) {
            for (InetAddress addr : addresses) {
                if (isForbidden(addr)) {
                    throw new DomainBlockedException(
                            "Scan bloqueado: o domínio aponta para um endereço interno/privado ("
                                    + addr.getHostAddress() + "). Apenas alvos públicos são permitidos.");
                }
            }
        }

        // Fixa os endereços já auditados: a próxima resolução deste host (a que o
        // HttpClient faz ao conectar) devolve estes mesmos objetos em vez de
        // consultar o DNS de novo. Ver SsrfPinningResolverProvider.
        ScanDnsPinRegistry.pin(normalized, List.of(addresses));
    }

    /**
     * Caracteres que um parser de URL lê como fim do host (userinfo, path, query,
     * fragmento) e espaço/controle. Nenhum aparece num host de verdade.
     */
    private static final Pattern URL_DELIMITERS = Pattern.compile("[@/?#\\\\\\s\\p{Cntrl}]");

    /**
     * Separa a porta de {@code host:porta} e {@code [ipv6]:porta} (e tira os colchetes
     * de {@code [ipv6]}) e recusa delimitadores de URL — o que sobra é exatamente o
     * host que um {@code URI} montado com este valor conectaria.
     *
     * Quem chama {@link #validateHost} recebe o host cru de um parâmetro e depois
     * monta {@code "https://" + host + ...} (ex. a verificação de posse). Sem isto, o
     * guard e o {@code URI} liam o mesmo texto de jeitos diferentes: com
     * {@code 127.0.0.1:8081}, {@code x@host-interno} ou {@code 127.0.0.1/}, o
     * {@code InetAddress} não resolvia e o guard deixava passar, mas o {@code URI}
     * extraía o host interno e a requisição saía (BUG-05). Porta em host público
     * continua valendo — domínio verificado pode ter porta ({@code juice-shop:3000}).
     *
     * IPv6 sem colchetes (mais de um {@code :}) volta como está.
     */
    private static String stripPort(String host) {
        if (URL_DELIMITERS.matcher(host).find()) {
            throw new DomainBlockedException("Host inválido para scan: '" + host
                    + "'. Informe só o domínio, sem caminho, espaço ou credenciais.");
        }

        String bare;
        String port;
        if (host.startsWith("[")) {
            int end = host.indexOf(']');
            String rest = end < 0 ? null : host.substring(end + 1);
            if (rest == null || (!rest.isEmpty() && !rest.startsWith(":"))) {
                throw new DomainBlockedException("Host inválido para scan: '" + host + "'.");
            }
            bare = host.substring(1, end);
            port = rest.isEmpty() ? null : rest.substring(1);
        } else {
            int colon = host.indexOf(':');
            if (colon < 0 || colon != host.lastIndexOf(':')) return host;
            bare = host.substring(0, colon);
            port = host.substring(colon + 1);
        }

        if (port != null && !port.matches("[0-9]{1,5}")) {
            throw new DomainBlockedException("Host inválido para scan: porta inválida em '" + host + "'.");
        }
        return bare;
    }

    /**
     * Recusa IPv4 escrito fora da forma canônica {@code a.b.c.d} decimal.
     *
     * Pela especificação de URL do WHATWG — a que navegadores e o curl seguem —, um
     * host cujo ÚLTIMO rótulo é numérico (decimal ou {@code 0x}-hex) é um IPv4, e cada
     * parte pode vir em hex ({@code 0x7f}), octal ({@code 0177}) ou decimal, com 1 a 4
     * partes ({@code 127.1}, {@code 2130706433}). O {@code InetAddress} do Java só
     * entende parte disso: converte as formas decimal e curta, mas trata o hex como
     * nome (não resolve → o guard deixava passar, BUG-02) e lê {@code 0177.0.0.1} como
     * 177.0.0.1 — público — onde um navegador lê 127.0.0.1.
     *
     * Validar e conectar com parsers que discordam é a receita clássica de SSRF. Em
     * vez de reimplementar todos os parsers e torcer para eles concordarem, a forma
     * ambígua é recusada na entrada, inclusive quando o destino seria público
     * ({@code 134744072} = 8.8.8.8): nenhum alvo legítimo precisa ser escrito assim.
     */
    private static void rejectNonCanonicalIpv4(String normalized, String original) {
        // A porta já saiu em stripPort: o que tem ':' aqui é literal IPv6 — o InetAddress cuida.
        if (normalized.indexOf(':') >= 0) return;

        String[] parts = normalized.split("\\.", -1);
        // "Ends in a number" do WHATWG: só dígitos (mesmo octal inválido, como "08") ou
        // um número válido em alguma base. Fora isso é hostname comum e segue para o DNS.
        String last = parts[parts.length - 1];
        boolean endsInNumber = last.matches("[0-9]+") || parseIpv4Part(last) >= 0;
        if (!endsInNumber || isCanonicalIpv4(parts)) return;

        String equivalent = whatwgIpv4(parts);
        throw new DomainBlockedException(equivalent != null
                ? "Scan bloqueado: '" + original + "' é um endereço IP em formato alternativo "
                        + "(equivale a " + equivalent + "). Informe o IP no formato decimal a.b.c.d."
                : "Scan bloqueado: '" + original + "' não é um endereço IP válido.");
    }

    /** Exatamente quatro octetos decimais, sem zero à esquerda, de 0 a 255. */
    private static boolean isCanonicalIpv4(String[] parts) {
        if (parts.length != 4) return false;
        for (String p : parts) {
            if (!p.matches("0|[1-9][0-9]{0,2}") || Integer.parseInt(p) > 255) return false;
        }
        return true;
    }

    /**
     * Interpreta o host como o parser IPv4 do WHATWG e devolve o {@code a.b.c.d}
     * equivalente, ou null se não for um IPv4 válido nessa leitura.
     */
    private static String whatwgIpv4(String[] parts) {
        int n = parts.length;
        if (n > 4) return null;

        long[] values = new long[n];
        for (int i = 0; i < n; i++) {
            values[i] = parseIpv4Part(parts[i]);
            if (values[i] < 0) return null;
            if (i < n - 1 && values[i] > 255) return null;
        }
        // A última parte preenche os bytes que sobraram: em "127.1", o 1 ocupa três.
        if (values[n - 1] >= 1L << (8 * (5 - n))) return null;

        long ipv4 = values[n - 1];
        for (int i = 0; i < n - 1; i++) ipv4 += values[i] << (8 * (3 - i));
        return ((ipv4 >> 24) & 0xFF) + "." + ((ipv4 >> 16) & 0xFF) + "."
                + ((ipv4 >> 8) & 0xFF) + "." + (ipv4 & 0xFF);
    }

    /**
     * Uma parte de IPv4 no WHATWG: {@code 0x}=hex, zero à esquerda=octal. -1 se não
     * for número. Sem limite de tamanho: {@code 0x00000000007f000001} ainda é
     * 127.0.0.1 para um navegador — cortar por comprimento deixaria essa forma cair
     * como hostname. Acima de 32 bits devolve 2^32, que nenhuma posição aceita.
     */
    private static long parseIpv4Part(String part) {
        if (part.isEmpty()) return -1;
        boolean hex   = part.startsWith("0x");
        boolean octal = !hex && part.length() > 1 && part.startsWith("0");
        int radix     = hex ? 16 : octal ? 8 : 10;
        String digits = hex ? part.substring(2) : octal ? part.substring(1) : part;
        if (digits.isEmpty()) return 0;   // "0x" sozinho vale 0, como no WHATWG
        if (!digits.chars().allMatch(c -> Character.digit(c, radix) >= 0)) return -1;
        BigInteger value = new BigInteger(digits, radix);
        return value.bitLength() > 32 ? 1L << 32 : value.longValue();
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
