package com.joao.cyberaudit.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Distinção entre um robots.txt de verdade e o index.html que hospedagens de
 * SPA devolvem para qualquer caminho.
 *
 * O bug que motivou estes testes: Cloudflare Pages responde 200 com o
 * index.html em /robots.txt, o parser não encontrava nenhuma linha `Disallow:`
 * no HTML e o módulo concluía "sem exposições" — carimbo verde num arquivo que
 * o site nunca serviu. Vale para todo alvo hospedado em SPA, não só para o
 * cyberauditapp.com.
 */
class RobotsTxtDetectionTest {

    private final RobotsTxtService service = new RobotsTxtService();

    private boolean pareceRobots(String body, String contentType) {
        return Boolean.TRUE.equals(ReflectionTestUtils.invokeMethod(
                service, "looksLikeRobotsTxt", body, contentType));
    }

    private static final String SPA_INDEX = """
            <!DOCTYPE html>
            <html lang="pt-BR">
              <head><meta charset="UTF-8" /><title>CyberAudit</title></head>
              <body><div id="root"></div></body>
            </html>
            """;

    @Test
    @DisplayName("index.html devolvido pela hospedagem de SPA não é robots.txt")
    void fallbackDeSpaNaoEhRobots() {
        assertFalse(pareceRobots(SPA_INDEX, "text/html; charset=utf-8"),
                "aceitar HTML como robots.txt produz laudo verde para arquivo inexistente");
    }

    @Test
    @DisplayName("HTML continua rejeitado mesmo se o servidor mentir o Content-Type")
    void htmlComContentTypeErradoAindaEhRejeitado() {
        assertFalse(pareceRobots(SPA_INDEX, "text/plain"),
                "o corpo começa com '<' — Content-Type não transforma HTML em robots.txt");
    }

    @Test
    @DisplayName("robots.txt legítimo é aceito")
    void robotsLegitimoEhAceito() {
        String body = "User-agent: *\nDisallow: /admin\nSitemap: https://exemplo.com/sitemap.xml";

        assertTrue(pareceRobots(body, "text/plain; charset=utf-8"));
    }

    @Test
    @DisplayName("Content-Type inesperado é aceito quando o corpo tem diretiva")
    void contentTypeInesperadoComDiretiva() {
        assertTrue(pareceRobots("User-agent: *\nDisallow:", "application/octet-stream"),
                "há servidor legítimo servindo robots.txt como octet-stream");
    }

    @Test
    @DisplayName("robots.txt vazio servido como text/plain conta como presente")
    void robotsVazioEhPresente() {
        assertTrue(pareceRobots("", "text/plain"),
                "arquivo vazio existe e significa 'sem restrições' — é diferente de não existir");
    }

    @Test
    @DisplayName("texto qualquer sem diretiva e sem text/plain não é robots.txt")
    void textoAleatorioNaoEhRobots() {
        assertFalse(pareceRobots("erro 404 - pagina nao encontrada", "application/octet-stream"));
    }

    @Test
    @DisplayName("corpo nulo não é robots.txt")
    void corpoNuloNaoEhRobots() {
        assertFalse(pareceRobots(null, "text/plain"));
    }
}
