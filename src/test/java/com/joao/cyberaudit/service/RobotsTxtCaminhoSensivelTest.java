package com.joao.cyberaudit.service;

import com.joao.cyberaudit.service.RobotsTxtService.Sonda;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Caminho no Disallow só é achado quando é sensível DE FATO e responde alguma
 * coisa DE FATO.
 *
 * Dois defeitos reais motivaram isto:
 *
 *  1. "/api/*" do eletroinga.com.br virava achado com -5 no score. O caminho
 *     devolve 404 — declarar no robots não expõe o que não existe. Já o
 *     "/admin/" de uma loja Nuvemshop devolve tela de login, e esse vale.
 *
 *  2. A comparação era por prefixo cru, então "/env" casava com "/envio" (frete)
 *     e "/dev" com "/devolucao" (trocas) — duas linhas presentes em quase toda
 *     loja brasileira, que é justamente o público do produto.
 */
class RobotsTxtCaminhoSensivelTest {

    private final RobotsTxtService service = new RobotsTxtService();

    // ── 1. Fronteira de segmento ─────────────────────────────────────────────

    @Test
    @DisplayName("caminho de loja brasileira nao casa por prefixo cru")
    void naoCasaPorPrefixoCru() {
        assertFalse(service.isSensitive("/envio/*"),      "/envio e frete, nao /env");
        assertFalse(service.isSensitive("/devolucao"),    "/devolucao e trocas, nao /dev");
        assertFalse(service.isSensitive("/testemunhos"),  "/testemunhos nao e /test");
        assertFalse(service.isSensitive("/configuracoes-loja"), "/configuracoes nao e /config");
    }

    @Test
    @DisplayName("o segmento sensivel de verdade continua casando")
    void segmentoSensivelCasa() {
        assertTrue(service.isSensitive("/admin/"));
        assertTrue(service.isSensitive("/admin"));
        assertTrue(service.isSensitive("/wp-admin/"));
        assertTrue(service.isSensitive("/.git/config"));
        assertTrue(service.isSensitive("/phpmyadmin"));
        assertTrue(service.isSensitive("/staging/*"));
    }

    @Test
    @DisplayName("pontuacao e fronteira valida: /backup.sql ainda e sensivel")
    void pontuacaoEhFronteira() {
        assertTrue(service.isSensitive("/backup.sql"));
        assertTrue(service.isSensitive("/config.php"));
        assertTrue(service.isSensitive("/db-dump"));
    }

    @Test
    @DisplayName("caminhos genericos sairam da lista")
    void genericosForaDaLista() {
        assertFalse(service.isSensitive("/api/*"),   "/api esta no robots de todo e-commerce");
        assertFalse(service.isSensitive("/api"));
        assertFalse(service.isSensitive("/uploads/"));
        assertFalse(service.isSensitive("/files/"));
    }

    // ── 2. Robots reais ──────────────────────────────────────────────────────

    /** robots.txt real do eletroinga.com.br, baixado do site. */
    private static final String ROBOTS_ELETROINGA = """
            User-agent: *
            Allow: /
            Disallow: /conta/*
            Disallow: /carrinho/*
            Disallow: /buscar
            Disallow: /documentacao
            Disallow: /api/*
            Disallow: /*fq=*
            Disallow: /compre_junto/*
            Disallow: /_events/*
            Disallow: /tracking/convertion
            Disallow: /static/*
            Disallow: /store/*
            Crawl-delay: 10
            """;

    /**
     * robots.txt real do brunoacabamentos.com.br (Nuvemshop) — inclusive a
     * repetição do bloco, que o arquivo de verdade tem.
     */
    private static final String ROBOTS_BRUNO = """
            User-agent: *
            Disallow: /admin/
            Disallow: /account/
            Disallow: /checkout/
            Disallow: /discount/
            Disallow: /blog/drafts/*
            Disallow: /comprar/
            Disallow: /search/
            Disallow: /frete/

            User-agent: Googlebot
            Disallow: /admin/
            Disallow: /account/
            Disallow: /checkout/
            """;

    @Test
    @DisplayName("robots do eletroinga nao gera candidato nenhum")
    void eletroingaSemCandidato() {
        assertEquals(List.of(), service.extractSensitivePaths(ROBOTS_ELETROINGA),
                "sao exclusoes de crawl budget, nao segredo");
    }

    @Test
    @DisplayName("robots do Bruno gera /admin/ uma vez, mesmo declarado em dois blocos")
    void brunoTemAdmin() {
        assertEquals(List.of("/admin/"), service.extractSensitivePaths(ROBOTS_BRUNO),
                "o arquivo real repete o bloco por User-agent");
    }

    @Test
    @DisplayName("Disallow repetido nao vira dois achados nem duas sondagens")
    void naoDuplica() {
        String robots = """
                User-agent: *
                Disallow: /admin/
                Disallow: /staging/

                User-agent: Bingbot
                Disallow: /admin/
                Disallow: /staging/
                """;

        assertEquals(List.of("/admin/", "/staging/"), service.extractSensitivePaths(robots));
    }

    // ── 3. Caminho sondável ──────────────────────────────────────────────────

    @Test
    @DisplayName("curinga do robots sai antes de sondar")
    void curingaSaiDoCaminho() {
        assertEquals("/api/",         service.caminhoParaSondar("/api/*"));
        assertEquals("/blog/drafts/", service.caminhoParaSondar("/blog/drafts/*"));
        assertEquals("/admin/",       service.caminhoParaSondar("/admin/"));
    }

    @Test
    @DisplayName("padrao que nao aponta para lugar nenhum nao e sondado")
    void padraoNaoEhCaminho() {
        assertNull(service.caminhoParaSondar("/*fq=*"));
        assertNull(service.caminhoParaSondar("*lid="));
        assertNull(service.caminhoParaSondar("/"));
        assertNull(service.caminhoParaSondar(""));
    }

    // ── 4. Decisão da sonda ──────────────────────────────────────────────────

    @Test
    @DisplayName("404 no caminho nao e achado, mesmo declarado no robots")
    void quatrocentosEQuatroNaoEhAchado() {
        Sonda controle = new Sonda(404, 52231);
        assertFalse(service.pareceExistir(controle, new Sonda(404, 52231)),
                "e o caso do /api/* do eletroinga");
    }

    @Test
    @DisplayName("pagina real com status diferente do lixo E achado")
    void paginaRealEhAchado() {
        Sonda controle = new Sonda(404, 1200);
        assertTrue(service.pareceExistir(controle, new Sonda(200, 8000)),
                "e o caso do /admin/ da loja Nuvemshop");
    }

    @Test
    @DisplayName("401 e 403 contam: existe, mas protegido")
    void protegidoEhAchado() {
        Sonda controle = new Sonda(404, 1200);
        assertTrue(service.pareceExistir(controle, new Sonda(401, 300)));
        assertTrue(service.pareceExistir(controle, new Sonda(403, 300)));
    }

    @Test
    @DisplayName("servidor catch-all nao transforma todo caminho em achado")
    void catchAllNaoEhAchado() {
        // Home devolvida com 200 para qualquer coisa: corpo praticamente igual.
        Sonda controle = new Sonda(200, 52000);
        assertFalse(service.pareceExistir(controle, new Sonda(200, 52010)));
        // Mas uma pagina de verdade tem corpo claramente diferente.
        assertTrue(service.pareceExistir(controle, new Sonda(200, 8000)));
    }

    @Test
    @DisplayName("erro de rede na sonda nao vira achado")
    void erroDeRedeNaoEhAchado() {
        assertFalse(service.pareceExistir(new Sonda(404, 100), null));
    }

    @Test
    @DisplayName("sem controle, so 200/401/403 passam")
    void semControle() {
        assertTrue(service.pareceExistir(null, new Sonda(200, 500)));
        assertTrue(service.pareceExistir(null, new Sonda(403, 500)));
        assertFalse(service.pareceExistir(null, new Sonda(302, 500)));
        assertFalse(service.pareceExistir(null, new Sonda(404, 500)));
    }
}
