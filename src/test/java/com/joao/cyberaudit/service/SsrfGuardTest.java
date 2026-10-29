package com.joao.cyberaudit.service;

import com.joao.cyberaudit.exception.DomainBlockedException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.InetAddress;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SsrfGuardTest {

    // Campo estático mutável em SsrfGuard — sem isto, um teste que a preenche
    // vazaria estado para os testes seguintes na mesma JVM.
    @AfterEach
    void limparAllowlist() {
        SsrfGuard.setTestAllowlist(Set.of());
    }

    // ── Esquemas ─────────────────────────────────────────────────────────────

    @ParameterizedTest
    @ValueSource(strings = {
            "file:///etc/passwd",
            "gopher://127.0.0.1:11211/_stats",
            "ftp://example.com/",
            "jar:http://example.com/a.jar!/",
            "dict://127.0.0.1:11211/",
            "ldap://example.com/",
            "//example.com/sem-esquema"
    })
    @DisplayName("rejeita esquemas fora de http/https")
    void rejeitaEsquemasNaoHttp(String url) {
        assertThrows(DomainBlockedException.class, () -> SsrfGuard.validate(url));
    }

    @Test
    @DisplayName("aceita http e https")
    void aceitaHttpEHttps() {
        assertDoesNotThrow(() -> SsrfGuard.validate("http://example.com"));
        assertDoesNotThrow(() -> SsrfGuard.validate("https://example.com/path?q=1"));
        assertDoesNotThrow(() -> SsrfGuard.validate("HTTPS://example.com"));
    }

    // ── Destinos internos por literal de IP ──────────────────────────────────

    @ParameterizedTest
    @ValueSource(strings = {
            "http://127.0.0.1/",
            "http://127.1.2.3/",
            "http://localhost/",
            "http://10.0.0.1/",
            "http://172.16.0.1/",
            "http://172.31.255.254/",
            "http://192.168.1.1/",
            "http://169.254.169.254/latest/meta-data/",   // metadata AWS/GCP/Azure
            "http://0.0.0.0/",
            "http://0.0.0.0:80/",
            "http://100.64.0.1/",                          // CGNAT
            "http://192.0.0.1/",                           // IETF protocol assignments
            "http://198.18.0.1/",                          // benchmark
            "http://255.255.255.255/",                     // broadcast
            "http://[::1]/",
            "http://[fc00::1]/",                           // ULA
            "http://[fe80::1]/",                           // link-local v6
            "http://[::ffff:169.254.169.254]/",            // v4 mapeado em v6
            "http://[::ffff:127.0.0.1]/",
            "http://[64:ff9b::a9fe:a9fe]/",                // NAT64 → 169.254.169.254
            "http://[2002:a9fe:a9fe::]/"                   // 6to4 → 169.254.169.254
    })
    @DisplayName("bloqueia loopback, redes privadas, metadata de cloud e IPv4 embutido em IPv6")
    void bloqueiaDestinosInternos(String url) {
        assertThrows(DomainBlockedException.class, () -> SsrfGuard.validate(url),
                "deveria bloquear " + url);
    }

    // ── Ofuscação ────────────────────────────────────────────────────────────

    @Test
    @DisplayName("bloqueia userinfo usado para mascarar o host real")
    void bloqueiaUserinfo() {
        assertThrows(DomainBlockedException.class,
                () -> SsrfGuard.validate("https://example.com@169.254.169.254/"));
        assertThrows(DomainBlockedException.class,
                () -> SsrfGuard.validate("https://user:pass@example.com/"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "http://localhost:8080/",
            "http://LOCALHOST/",
            "http://algo.localhost/",
            "http://db.internal/",
            "http://printer.local/",
            "http://host.home.arpa/",
            "http://localhost./"        // ponto final (FQDN raiz)
    })
    @DisplayName("bloqueia nomes de rede interna independente de resolução")
    void bloqueiaNomesInternos(String url) {
        assertThrows(DomainBlockedException.class, () -> SsrfGuard.validate(url),
                "deveria bloquear " + url);
    }

    // ── Formas numéricas alternativas de IPv4 (BUG-02, cyberaudit-qa) ─────────

    @ParameterizedTest
    @ValueSource(strings = {
            "http://0x7f000001/",       // hex inteiro → 127.0.0.1 (o caso do BUG-02)
            "http://0X7F000001/",       // hex maiúsculo
            "http://0x7f.0.0.1/",       // hex por octeto
            "http://0x7f.1/",           // hex + forma curta
            "http://0x00000000000000007f000001/",  // hex com zeros à esquerda (qualquer tamanho)
            "http://0xa9fea9fe/",       // hex → 169.254.169.254 (metadata cloud)
            "http://017700000001/",     // octal inteiro → 127.0.0.1
            "http://0177.0.0.1/",       // octal por octeto: o JDK lê 177.0.0.1 (público!),
                                        // navegador e curl leem 127.0.0.1
            "http://2130706433/",       // decimal inteiro → 127.0.0.1
            "http://127.1/",            // forma curta → 127.0.0.1
            "http://127.0.0.01/",       // zero à esquerda num octeto
            "http://134744072/",        // decimal inteiro de IP PÚBLICO (8.8.8.8) — também
                                        // ambíguo, recusado pelo formato e não pelo destino
            "http://1.2.3.4.5/",        // cinco partes: não é IPv4 válido
            "http://999999999999/"      // estoura 32 bits
    })
    @DisplayName("recusa IPv4 fora da forma canônica a.b.c.d (hex, octal, inteiro, curta)")
    void recusaIpv4NaoCanonico(String url) {
        assertThrows(DomainBlockedException.class, () -> SsrfGuard.validate(url),
                "deveria bloquear " + url);
    }

    @Test
    @DisplayName("a mensagem diz a qual endereço a forma alternativa equivale")
    void mensagemMostraEquivalente() {
        DomainBlockedException e = assertThrows(DomainBlockedException.class,
                () -> SsrfGuard.validate("http://0x7f000001/"));
        assertTrue(e.getMessage().contains("127.0.0.1"), e.getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "http://8.8.8.8/",              // IPv4 canônico público continua aceito
            "http://0x7f000001.invalid/",   // só o ÚLTIMO rótulo decide se é IP; .invalid
            "http://123.invalid/"           // nunca resolve (RFC 6761), então segue
    })
    @DisplayName("IPv4 canônico público e hostnames com rótulos numéricos não são recusados pelo formato")
    void naoRecusaFormaCanonicaNemHostname(String url) {
        assertDoesNotThrow(() -> SsrfGuard.validate(url));
    }

    // ── Host com porta ou delimitador (BUG-05, cyberaudit-qa) ─────────────────

    @ParameterizedTest
    @ValueSource(strings = {
            "127.0.0.1:8081",           // porta: o InetAddress não resolvia → passava
            "localhost:8081",           // e o sufixo "localhost" não casava com ":8081"
            "169.254.169.254:80",
            "0x7f000001:80",            // porta + forma alternativa (BUG-02)
            "[::1]:443",
            "10.0.0.1:",                // porta vazia
            "127.0.0.1:abc",            // porta não numérica
            " 127.0.0.1",               // espaço: quem usa o host apara antes de montar a URL
            "127.0.0.1 ",
            "x@example.com",            // userinfo: o URI leria o host como example.com
            "example.com/caminho",      // path, query e fragmento: idem
            "example.com?q=1",
            "example.com#frag",
            "exa mple.com",
            ":8080"                     // só porta, sem host
    })
    @DisplayName("validateHost recusa host disfarçado por porta interna, espaço ou delimitador de URL")
    void validateHostRecusaHostDisfarcado(String host) {
        assertThrows(DomainBlockedException.class, () -> SsrfGuard.validateHost(host),
                "deveria bloquear '" + host + "'");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "8.8.8.8:443",
            "[2606:4700:4700::1111]:443",
            "example.invalid:8443"      // porta em host público é legítima (domínio verificado com porta)
    })
    @DisplayName("validateHost aceita porta em host público — a porta não muda o destino validado")
    void validateHostAceitaPortaEmHostPublico(String host) {
        assertDoesNotThrow(() -> SsrfGuard.validateHost(host));
    }

    @Test
    @DisplayName("allowlist de teste casa pelo host sem a porta (juice-shop:3000 → juice-shop)")
    void allowlistCasaSemPorta() {
        // O seed do cyberaudit-qa guarda domínios com porta (juice-shop:3000). Antes, eles
        // passavam pelo mesmo buraco do BUG-05; agora passam porque o host está na allowlist.
        SsrfGuard.setTestAllowlist(Set.of("192.168.1.100"));
        assertDoesNotThrow(() -> SsrfGuard.validateHost("192.168.1.100:3000"));
        assertThrows(DomainBlockedException.class, () -> SsrfGuard.validateHost("192.168.1.101:3000"));
    }

    // ── URLs inválidas ───────────────────────────────────────────────────────

    @ParameterizedTest
    @ValueSource(strings = {"", "   ", "https://", "http://:80/"})
    @DisplayName("rejeita URL vazia ou sem host")
    void rejeitaUrlSemHost(String url) {
        assertThrows(DomainBlockedException.class, () -> SsrfGuard.validate(url));
    }

    @Test
    @DisplayName("rejeita URL nula")
    void rejeitaUrlNula() {
        assertThrows(DomainBlockedException.class, () -> SsrfGuard.validate(null));
    }

    // ── isForbidden / isAllowed ──────────────────────────────────────────────

    @Test
    @DisplayName("isForbidden cobre as faixas reservadas e libera IP público")
    void isForbiddenCobreFaixas() throws Exception {
        assertTrue(SsrfGuard.isForbidden(InetAddress.getByName("169.254.169.254")));
        assertTrue(SsrfGuard.isForbidden(InetAddress.getByName("192.168.0.1")));
        assertTrue(SsrfGuard.isForbidden(InetAddress.getByName("::1")));
        assertTrue(SsrfGuard.isForbidden(null));
        assertFalse(SsrfGuard.isForbidden(InetAddress.getByName("8.8.8.8")));
        assertFalse(SsrfGuard.isForbidden(InetAddress.getByName("2606:4700:4700::1111")));
    }

    @Test
    @DisplayName("isAllowed não lança e reflete a decisão do validate")
    void isAllowedNaoLanca() {
        assertFalse(SsrfGuard.isAllowed("http://169.254.169.254/"));
        assertFalse(SsrfGuard.isAllowed("file:///etc/passwd"));
        assertTrue(SsrfGuard.isAllowed("https://example.com"));
    }

    // ── Allowlist de teste (cyberaudit-qa, profile qa-docker) ────────────────

    @Test
    @DisplayName("allowlist vazia (padrão/produção) não muda nada — IP privado continua bloqueado")
    void allowlistVaziaPorPadrao() {
        assertThrows(DomainBlockedException.class, () -> SsrfGuard.validateHost("192.168.1.100"));
    }

    @Test
    @DisplayName("host na allowlist de teste passa mesmo sendo endereço privado")
    void allowlistLiberaHostEspecifico() {
        assertThrows(DomainBlockedException.class, () -> SsrfGuard.validateHost("192.168.1.100"),
                "sanity check: sem allowlist, bloqueado");

        SsrfGuard.setTestAllowlist(Set.of("192.168.1.100"));

        assertDoesNotThrow(() -> SsrfGuard.validateHost("192.168.1.100"));
        // Só o host exato liberado passa — outro IP privado qualquer continua bloqueado.
        assertThrows(DomainBlockedException.class, () -> SsrfGuard.validateHost("192.168.1.101"));
    }

    @Test
    @DisplayName("allowlist não libera nomes de rede interna (BLOCKED_SUFFIXES continua valendo)")
    void allowlistNaoContornaBlockedSuffixes() {
        SsrfGuard.setTestAllowlist(Set.of("localhost"));
        assertThrows(DomainBlockedException.class, () -> SsrfGuard.validateHost("localhost"),
                "allowlist só afasta a checagem de IP — nomes bloqueados por suffix continuam bloqueados");
    }
}
