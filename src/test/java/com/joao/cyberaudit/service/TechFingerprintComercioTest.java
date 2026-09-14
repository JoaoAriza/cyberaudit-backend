package com.joao.cyberaudit.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Reconhecimento de plataforma de loja.
 *
 * O fingerprint só conhecia Shopify, e a maioria das lojas que aparecem na
 * prospecção pelo Maps roda em VTEX, Nuvemshop, WooCommerce ou Magento. Saber a
 * plataforma separa o que o lojista consegue consertar do que é da plataforma.
 */
class TechFingerprintComercioTest {

    private String html(String corpo) {
        return ("<html><head>" + corpo + "</head><body></body></html>").toLowerCase();
    }

    @Test
    @DisplayName("VTEX pelo domínio de asset")
    void vtexPorAsset() {
        assertEquals("VTEX", TechFingerprintService.plataformaDeLoja(
                html("<img src=\"https://lojaexemplo.vteximg.com.br/arquivos/logo.png\">"), List.of(), Map.of()));
    }

    @Test
    @DisplayName("VTEX pelo header próprio, mesmo sem marcador no HTML")
    void vtexPorHeader() {
        assertEquals("VTEX", TechFingerprintService.plataformaDeLoja(
                html(""), List.of(), Map.of("X-VTEX-Cache-Status-Janus-ApiCache", List.of("MISS"))));
    }

    @Test
    @DisplayName("Nuvemshop pelo CDN da Tiendanube")
    void nuvemshop() {
        assertEquals("Nuvemshop", TechFingerprintService.plataformaDeLoja(
                html("<link href=\"//d26lpennugtm8s.cloudfront.net/stores/001/234/themes/common/css.css\">"),
                List.of(), Map.of()));
    }

    @Test
    @DisplayName("Loja Integrada pelo CDN próprio")
    void lojaIntegrada() {
        // Marcador tirado de uma loja real da prospecção (eletroinga), que não tinha
        // nenhum dos outros: CSS e JS da loja saem todos de cdn.awsli.com.br.
        assertEquals("Loja Integrada", TechFingerprintService.plataformaDeLoja(
                html("<link rel=\"stylesheet\" href=\"https://cdn.awsli.com.br/production/static/loja/estrutura/v1/css/all.min.css\">"),
                List.of(), Map.of()));
    }

    @Test
    @DisplayName("WooCommerce pelo plugin, dentro de um WordPress")
    void wooCommerce() {
        assertEquals("WooCommerce", TechFingerprintService.plataformaDeLoja(
                html("<link href=\"/wp-content/plugins/woocommerce/assets/css/woocommerce.css\">"),
                List.of(), Map.of()));
    }

    @Test
    @DisplayName("WooCommerce pelo cookie de sessão do carrinho")
    void wooCommercePorCookie() {
        assertEquals("WooCommerce", TechFingerprintService.plataformaDeLoja(
                html(""), List.of("wp_woocommerce_session_abc123=xyz; path=/"), Map.of()));
    }

    @Test
    @DisplayName("Magento pelo script de inicialização")
    void magento() {
        assertEquals("Magento", TechFingerprintService.plataformaDeLoja(
                html("<script type=\"text/x-magento-init\">{}</script>"), List.of(), Map.of()));
    }

    @Test
    @DisplayName("nome da plataforma no texto não é loja: agência que 'faz lojas VTEX e Nuvemshop'")
    void mencaoNoTextoNaoCasa() {
        assertNull(TechFingerprintService.plataformaDeLoja(
                html("<p>Criamos lojas VTEX, Nuvemshop, WooCommerce e Magento para o seu negócio.</p>"),
                List.of(), Map.of()));
    }

    @Test
    @DisplayName("site sem nada de loja não inventa plataforma")
    void siteComum() {
        assertNull(TechFingerprintService.plataformaDeLoja(
                html("<a href=\"https://wa.me/5511999999999\">WhatsApp</a>"), List.of("PHPSESSID=1"), Map.of()));
    }
}
