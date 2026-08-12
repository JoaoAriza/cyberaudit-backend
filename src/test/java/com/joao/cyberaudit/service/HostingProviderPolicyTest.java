package com.joao.cyberaudit.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Regras vindas do suporte do Render: o scanner não pode sondar sistemas do
 * provedor nem infraestrutura compartilhada de outros inquilinos.
 */
class HostingProviderPolicyTest {

    private final HostingProviderPolicy policy =
            new HostingProviderPolicy("render.com", "onrender.com");

    // ── Infraestrutura do provedor: nunca escaneada ──────────────────────────

    @Test
    @DisplayName("propriedades do provedor são bloqueadas, com ou sem subdomínio")
    void bloqueiaInfraDoProvedor() {
        assertTrue(policy.isProviderInfrastructure("render.com"));
        assertTrue(policy.isProviderInfrastructure("api.render.com"));
        assertTrue(policy.isProviderInfrastructure("dashboard.render.com"));
        assertTrue(policy.isProviderInfrastructure("dpg-abc-a.oregon-postgres.render.com"));
    }

    @Test
    @DisplayName("comparação é por rótulo, não por 'contém' — não pega domínio parecido")
    void naoPegaDominioParecido() {
        assertFalse(policy.isProviderInfrastructure("render.com.br"));
        assertFalse(policy.isProviderInfrastructure("notrender.com"));
        assertFalse(policy.isProviderInfrastructure("meurender.com"));
        assertFalse(policy.isProviderInfrastructure("render.com.evil.net"));
    }

    @Test
    @DisplayName("site de cliente comum passa normalmente")
    void clienteComumPassa() {
        assertFalse(policy.isProviderInfrastructure("example.com"));
        assertFalse(policy.isProviderInfrastructure("cyberauditapp.com"));
    }

    // ── Port scan em infraestrutura compartilhada ────────────────────────────

    @Test
    @DisplayName("port scan é recusado em *.onrender.com — as portas são da borda do Render")
    void portScanRecusadoEmInfraCompartilhada() {
        assertTrue(policy.isPortScanForbidden("meuapp.onrender.com"));
        assertTrue(policy.isPortScanForbidden("cyberaudit-backend.onrender.com"));
    }

    @Test
    @DisplayName("port scan também é recusado nas propriedades do provedor")
    void portScanRecusadoNaInfraDoProvedor() {
        assertTrue(policy.isPortScanForbidden("api.render.com"));
    }

    @Test
    @DisplayName("port scan segue liberado em domínio próprio do cliente")
    void portScanLiberadoNoDominioDoCliente() {
        assertFalse(policy.isPortScanForbidden("example.com"));
        assertFalse(policy.isPortScanForbidden("app.cliente.com.br"));
    }

    // ── Normalização e configuração ──────────────────────────────────────────

    @Test
    @DisplayName("caixa e ponto final do FQDN não escapam da regra")
    void normalizaHost() {
        assertTrue(policy.isProviderInfrastructure("API.RENDER.COM"));
        assertTrue(policy.isProviderInfrastructure("api.render.com."));
        assertTrue(policy.isProviderInfrastructure("  api.render.com  "));
    }

    @Test
    @DisplayName("host nulo ou vazio não quebra")
    void hostVazio() {
        assertFalse(policy.isProviderInfrastructure(null));
        assertFalse(policy.isProviderInfrastructure(""));
        assertFalse(policy.isPortScanForbidden(null));
    }

    @Test
    @DisplayName("lista vazia desliga a regra — permite trocar de provedor por config")
    void listaVaziaDesligaRegra() {
        HostingProviderPolicy semRestricao = new HostingProviderPolicy("", "");

        assertFalse(semRestricao.isProviderInfrastructure("render.com"));
        assertFalse(semRestricao.isPortScanForbidden("meuapp.onrender.com"));
    }

    @Test
    @DisplayName("aceita múltiplos sufixos separados por vírgula")
    void multiplosSufixos() {
        HostingProviderPolicy multi =
                new HostingProviderPolicy("render.com, fly.io ,railway.app", "onrender.com");

        assertTrue(multi.isProviderInfrastructure("api.fly.io"));
        assertTrue(multi.isProviderInfrastructure("railway.app"));
        assertFalse(multi.isProviderInfrastructure("example.com"));
    }
}
