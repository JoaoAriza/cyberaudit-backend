package com.joao.cyberaudit.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Política de domínio (crossdomain.xml / clientaccesspolicy.xml) só é achado
 * quando libera demais.
 *
 * Esses arquivos são PÚBLICOS por natureza, como o robots.txt — existir não é
 * exposição. O caso real que motivou: brunoacabamentos.com.br, loja Nuvemshop,
 * servia uma política restrita a *.tiendanube.com, *.nuvemshop.com.br e a uma
 * distribuição CloudFront nominal. Arquivo colocado pela plataforma, configuração
 * correta, e mesmo assim vinha como "arquivo sensível exposto, MEDIUM".
 */
class CrossdomainPolicyTest {

    private final SensitiveFileService service = new SensitiveFileService();

    /** A política real do brunoacabamentos.com.br, baixada do site. */
    private String politicaDoBruno() {
        return "<?xml version=\"1.0\"?>\n"
             + "<!DOCTYPE cross-domain-policy SYSTEM \"http://www.macromedia.com/xml/dtds/cross-domain-policy.dtd\">\n"
             + "<cross-domain-policy>\n"
             + "    <allow-access-from domain=\"*.tiendanube.com\" />\n"
             + "    <allow-access-from domain=\"*.nuvemshop.com.br\" />\n"
             + "    <allow-access-from domain=\"d26lpennugtm8s.cloudfront.net\" />\n"
             + "</cross-domain-policy>";
    }

    private String politica(String miolo) {
        return "<?xml version=\"1.0\"?>\n<cross-domain-policy>\n" + miolo + "\n</cross-domain-policy>";
    }

    // ── Não é achado ─────────────────────────────────────────────────────────

    @Test
    @DisplayName("politica restrita a dominios nomeados NAO e reportada")
    void politicaRestritaNaoEhAchado() {
        assertFalse(service.isRealContent("/crossdomain.xml", politicaDoBruno(), "text/xml"),
                "politica da plataforma, corretamente restrita, nao e exposicao");
    }

    @Test
    @DisplayName("distribuicao CloudFront nominal e uso correto, nao curinga")
    void cloudfrontNominalNaoEhAchado() {
        assertFalse(service.politicaPermissiva(
                politica("<allow-access-from domain=\"d26lpennugtm8s.cloudfront.net\" />")));
    }

    @Test
    @DisplayName("XML que nao e politica de dominio continua fora")
    void xmlQualquerNaoEhAchado() {
        assertFalse(service.isRealContent("/crossdomain.xml",
                "<?xml version=\"1.0\"?><urlset><url><loc>https://site.com/</loc></url></urlset>", "text/xml"));
    }

    // ── É achado ─────────────────────────────────────────────────────────────

    @Test
    @DisplayName("domain=* libera qualquer origem e E reportado")
    void curingaTotalEhAchado() {
        assertTrue(service.isRealContent("/crossdomain.xml",
                politica("<allow-access-from domain=\"*\" />"), "text/xml"));
    }

    @Test
    @DisplayName("curinga em hospedagem compartilhada E reportado")
    void curingaEmHospedagemCompartilhadaEhAchado() {
        // Qualquer um cria uma distribuicao em cloudfront.net e herda a confianca.
        assertTrue(service.politicaPermissiva(
                politica("<allow-access-from domain=\"*.cloudfront.net\" />")));
        assertTrue(service.politicaPermissiva(
                politica("<allow-access-from domain=\"*.herokuapp.com\" />")));
        assertTrue(service.politicaPermissiva(
                politica("<allow-access-from domain=\"*.s3.amazonaws.com\" />")));
    }

    @Test
    @DisplayName("headers=* e secure=false sao permissivos")
    void headersEsecureEhAchado() {
        assertTrue(service.politicaPermissiva(
                politica("<allow-http-request-headers-from domain=\"site.com\" headers=\"*\" />")));
        assertTrue(service.politicaPermissiva(
                politica("<allow-access-from domain=\"site.com\" secure=\"false\" />")));
    }

    @Test
    @DisplayName("Silverlight: uri=* e reportado, escopo nominal nao")
    void silverlight() {
        String aberto = "<access-policy><cross-domain-access><policy>"
                + "<allow-from><domain uri=\"*\"/></allow-from>"
                + "<grant-to><resource path=\"/\" include-subpaths=\"true\"/></grant-to>"
                + "</policy></cross-domain-access></access-policy>";
        String fechado = "<access-policy><cross-domain-access><policy>"
                + "<allow-from><domain uri=\"https://app.tiendanube.com\"/></allow-from>"
                + "<grant-to><resource path=\"/api\"/></grant-to>"
                + "</policy></cross-domain-access></access-policy>";

        assertTrue(service.isRealContent("/clientaccesspolicy.xml", aberto, "text/xml"));
        assertFalse(service.isRealContent("/clientaccesspolicy.xml", fechado, "text/xml"));
    }

    @Test
    @DisplayName("aspas simples e espacos nao escapam da deteccao")
    void variacoesDeSintaxe() {
        assertTrue(service.politicaPermissiva(politica("<allow-access-from domain='*' />")));
        assertTrue(service.politicaPermissiva(politica("<allow-access-from domain = \"*\" />")));
        assertTrue(service.politicaPermissiva(politica("<allow-access-from DOMAIN=\"*\" />")));
    }
}
