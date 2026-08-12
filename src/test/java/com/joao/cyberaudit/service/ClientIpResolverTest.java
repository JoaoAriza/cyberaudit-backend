package com.joao.cyberaudit.service;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ClientIpResolverTest {

    private static final String REAL   = "203.0.113.9";   // cliente de verdade
    private static final String FORJADO = "1.2.3.4";      // o que o atacante escreve
    private static final String PEER   = "10.0.0.5";      // quem abriu a conexão TCP

    private HttpServletRequest request(String xff) {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getRemoteAddr()).thenReturn(PEER);
        when(req.getHeader(eq("X-Forwarded-For"))).thenReturn(xff);
        return req;
    }

    // ── Sem proxy ────────────────────────────────────────────────────────────

    @Test
    @DisplayName("sem proxy configurado, o header é ignorado por completo")
    void semProxyIgnoraHeader() {
        var resolver = new ClientIpResolver(0);

        assertEquals(PEER, resolver.resolve(request(FORJADO)),
                "com 0 proxies o X-Forwarded-For não vale nada");
    }

    // ── Um proxy (Render, nginx, Tunnel) ─────────────────────────────────────

    @Test
    @DisplayName("proxy que APENDA: pega o valor que o proxy escreveu, não o do atacante")
    void umProxyIgnoraValorForjado() {
        var resolver = new ClientIpResolver(1);

        // O cliente mandou "1.2.3.4"; o Render acrescentou o IP real ao final.
        assertEquals(REAL, resolver.resolve(request(FORJADO + ", " + REAL)));
    }

    @Test
    @DisplayName("proxy que SUBSTITUI: header com um valor só funciona igual")
    void umProxyComHeaderLimpo() {
        var resolver = new ClientIpResolver(1);

        assertEquals(REAL, resolver.resolve(request(REAL)));
    }

    @Test
    @DisplayName("vários valores forjados não mudam o resultado")
    void variosValoresForjados() {
        var resolver = new ClientIpResolver(1);

        assertEquals(REAL, resolver.resolve(
                request("9.9.9.9, 8.8.8.8, " + FORJADO + ", " + REAL)));
    }

    // ── Dois proxies (Cloudflare na frente) ──────────────────────────────────

    @Test
    @DisplayName("dois proxies: pula a borda do Cloudflare e pega o cliente real")
    void doisProxies() {
        var resolver = new ClientIpResolver(2);

        // forjado, real (escrito pelo CF), borda do CF (escrita pelo Render)
        assertEquals(REAL, resolver.resolve(request(FORJADO + ", " + REAL + ", 172.71.0.1")));
    }

    // ── Falha segura ─────────────────────────────────────────────────────────

    @Test
    @DisplayName("cadeia mais curta que o esperado cai para o peer, não adivinha")
    void cadeiaCurtaCaiParaPeer() {
        var resolver = new ClientIpResolver(2);

        // Só um valor, mas esperávamos dois saltos: não dá para saber o que é
        // confiável. Falhar para o peer aperta o limite; nunca o afrouxa.
        assertEquals(PEER, resolver.resolve(request(FORJADO)));
    }

    @Test
    @DisplayName("header ausente ou vazio cai para o peer")
    void headerAusente() {
        var resolver = new ClientIpResolver(1);

        assertEquals(PEER, resolver.resolve(request(null)));
        assertEquals(PEER, resolver.resolve(request("   ")));
    }

    @Test
    @DisplayName("request nulo não lança")
    void requestNulo() {
        assertEquals("desconhecido", new ClientIpResolver(1).resolve(null));
    }

    @Test
    @DisplayName("configuração negativa é tratada como zero proxies")
    void configuracaoNegativa() {
        assertEquals(PEER, new ClientIpResolver(-3).resolve(request(FORJADO)));
    }

    // ── Normalização ─────────────────────────────────────────────────────────

    @Test
    @DisplayName("porta é removida — senão o mesmo cliente vira um IP novo a cada conexão")
    void removePorta() {
        var resolver = new ClientIpResolver(1);

        assertEquals(REAL, resolver.resolve(request(FORJADO + ", " + REAL + ":53812")));
    }

    @Test
    @DisplayName("IPv6 entre colchetes com porta é normalizado")
    void normalizaIpv6() {
        var resolver = new ClientIpResolver(1);

        assertEquals("2001:db8::1", resolver.resolve(request(FORJADO + ", [2001:db8::1]:443")));
    }

    @Test
    @DisplayName("IPv6 puro é preservado inteiro")
    void ipv6Puro() {
        var resolver = new ClientIpResolver(1);

        assertEquals("2001:db8::1", resolver.resolve(request("2001:db8::1")));
    }

    @Test
    @DisplayName("espaços em volta das vírgulas não afetam")
    void toleraEspacos() {
        var resolver = new ClientIpResolver(1);

        assertEquals(REAL, resolver.resolve(request(FORJADO + "  ,   " + REAL + "  ")));
    }
}
