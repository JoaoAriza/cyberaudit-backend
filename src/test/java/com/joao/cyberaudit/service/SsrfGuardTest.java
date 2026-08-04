package com.joao.cyberaudit.service;

import com.joao.cyberaudit.exception.DomainBlockedException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.InetAddress;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SsrfGuardTest {

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
}
