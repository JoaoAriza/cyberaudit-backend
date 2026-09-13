package com.joao.cyberaudit.service;

import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

@Service
public class RobotsTxtService {

    /**
     * Prefixos que VALEM a pena sondar quando aparecem num Disallow.
     *
     * Não é a lista do que é vulnerável — é a lista do que merece uma
     * verificação. O que decide o achado é a sonda: o caminho responder algo
     * real. Por isso caminhos genéricos saíram daqui: "/api" está no robots de
     * praticamente todo e-commerce por crawl budget, e sondá-lo só gastava
     * requisição para reportar ruído.
     */
    private static final Set<String> SENSITIVE_PREFIXES = Set.of(
            "/admin", "/administrator",
            "/backup", "/backups",
            "/config", "/configuration",
            "/db", "/database",
            "/private", "/secret",
            "/staging", "/dev", "/test",
            "/.git", "/.env",
            "/phpmyadmin",
            "/wp-admin", "/wp-login",
            "/logs", "/debug",
            "/console", "/actuator", "/env"
    );

    /** Diretivas que identificam um robots.txt de verdade quando o Content-Type não ajuda. */
    private static final Set<String> ROBOTS_DIRECTIVES = Set.of(
            "user-agent:", "disallow:", "allow:", "sitemap:", "crawl-delay:");

    /** Diferença de corpo, em bytes, a partir da qual duas respostas são páginas distintas. */
    private static final int DIFERENCA_MINIMA_CORPO = 256;

    private final HttpClient client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)  // redirects seguidos por ScannerHttp.sendFollowingSafely (revalida cada hop)
            .connectTimeout(Duration.ofSeconds(6))
            .build();

    /**
     * Resultado do módulo: presença do arquivo e paths sensíveis declarados.
     *
     * Sem o `present`, "o site não tem robots.txt" e "o robots.txt não expõe
     * nada" produziam exatamente a mesma resposta — uma lista vazia — e a UI
     * dava OK nos dois casos, afirmando ter analisado um arquivo inexistente.
     */
    public record RobotsTxtResult(boolean present, List<String> sensitivePaths) {
        public static RobotsTxtResult ausente() {
            return new RobotsTxtResult(false, List.of());
        }
    }

    /** Resposta de uma sondagem: o que basta para decidir se o caminho existe. */
    record Sonda(int status, int tamanho) {}

    public RobotsTxtResult check(String baseUrl) {
        String origem = origemDe(baseUrl);
        String body = fetchRobots(origem + "/robots.txt");
        if (body == null) return RobotsTxtResult.ausente();

        List<String> candidatos = extractSensitivePaths(body);
        return new RobotsTxtResult(true, confirmar(origem, candidatos));
    }

    /**
     * Mantém só os candidatos que respondem alguma coisa de verdade.
     *
     * Declarar um caminho no Disallow não expõe nada se o caminho não existe —
     * e era isso que o módulo reportava: "/api/*" do eletroinga.com.br devolve
     * 404, e mesmo assim virava achado com -5 no score. Já o "/admin/" de uma
     * loja Nuvemshop devolve a tela de login, e esse continua valendo.
     *
     * A sonda de controle existe por causa do servidor catch-all, que responde
     * 200 com a home para qualquer caminho: sem ela, TODO candidato "existiria".
     */
    private List<String> confirmar(String origem, List<String> candidatos) {
        if (candidatos.isEmpty()) return List.of();

        Sonda controle = sondar(origem + "/cyberaudit-nao-existe-"
                + Long.toHexString(System.nanoTime()));

        List<String> confirmados = new ArrayList<>();
        for (String candidato : candidatos) {
            String caminho = caminhoParaSondar(candidato);
            if (caminho == null) continue;
            if (pareceExistir(controle, sondar(origem + caminho))) confirmados.add(candidato);
        }
        return confirmados;
    }

    /**
     * O caminho respondeu algo diferente do que o servidor responde para lixo?
     *
     * 401/403 contam: significam "existe, mas é protegido" — o Disallow revelou
     * um recurso real. 404/410 não contam. Sem controle (erro de rede na sonda
     * de referência), só um 2xx/4xx-de-autenticação explícito passa.
     */
    boolean pareceExistir(Sonda controle, Sonda alvo) {
        if (alvo == null) return false;
        if (alvo.status() == 404 || alvo.status() == 410) return false;

        if (controle == null) {
            return alvo.status() == 200 || alvo.status() == 401 || alvo.status() == 403;
        }
        // Status diferente do lixo = o servidor distingue esse caminho.
        if (alvo.status() != controle.status()) return true;

        // Mesmo status: só é página distinta se o corpo for claramente outro —
        // é o que separa o /admin real do site que devolve a home para tudo.
        return Math.abs(alvo.tamanho() - controle.tamanho()) > DIFERENCA_MINIMA_CORPO;
    }

    /**
     * Converte a linha do Disallow num caminho sondável, ou null quando ela é um
     * padrão e não um caminho.
     *
     * O "*" do robots é curinga, não parte da URL — pedir "/api/*" literalmente
     * sempre dá 404, inclusive na conferência manual. Regras como "/*fq=*" ou
     * "*lid=" não apontam para lugar nenhum e não têm o que sondar.
     */
    String caminhoParaSondar(String path) {
        if (path == null || path.isBlank()) return null;

        String caminho = path.trim();
        int curinga = caminho.indexOf('*');
        if (curinga >= 0) caminho = caminho.substring(0, curinga);

        int query = caminho.indexOf('?');
        if (query >= 0) caminho = caminho.substring(0, query);

        caminho = caminho.trim();
        if (!caminho.startsWith("/")) return null;
        if (caminho.equals("/")) return null;
        return caminho;
    }

    List<String> extractSensitivePaths(String body) {
        // Conjunto, e não lista: robots.txt repete o mesmo Disallow em cada bloco
        // de User-agent. O brunoacabamentos.com.br declara "/admin/" duas vezes, e
        // isso virava "2 paths sensíveis" para um caminho só — além de sondar a
        // mesma URL duas vezes. LinkedHashSet preserva a ordem do arquivo.
        Set<String> found = new LinkedHashSet<>();
        try {
            for (String line : body.split("\\r?\\n")) {
                line = line.trim();
                if (!line.toLowerCase(Locale.ROOT).startsWith("disallow:")) continue;

                String path = line.substring("disallow:".length()).trim();
                int commentIdx = path.indexOf('#');
                if (commentIdx >= 0) path = path.substring(0, commentIdx).trim();

                if (isSensitive(path)) found.add(path);
            }
        } catch (Exception ignored) {}
        return new ArrayList<>(found);
    }

    /**
     * O caminho começa por um segmento sensível?
     *
     * Comparação por SEGMENTO, e não por prefixo cru: "/envio/*" (frete) e
     * "/devolucao" (trocas) estão em quase toda loja brasileira e casavam com
     * "/env" e "/dev" no startsWith. A fronteira aceita pontuação — "/backup.sql"
     * ainda casa com "/backup", porque ali o segmento de fato começa pela palavra.
     */
    boolean isSensitive(String path) {
        if (path == null || path.isBlank() || path.equals("/")) return false;

        String lower = path.toLowerCase(Locale.ROOT);
        int curinga = lower.indexOf('*');
        if (curinga >= 0) lower = lower.substring(0, curinga);
        if (!lower.startsWith("/")) return false;

        for (String prefixo : SENSITIVE_PREFIXES) {
            if (casaPorSegmento(lower, prefixo)) return true;
        }
        return false;
    }

    /** "/admin/x" casa com "/admin"; "/envio" não casa com "/env". */
    private boolean casaPorSegmento(String caminho, String prefixo) {
        if (!caminho.startsWith(prefixo)) return false;
        if (caminho.length() == prefixo.length()) return true;

        char seguinte = caminho.charAt(prefixo.length());
        // Letra ou dígito logo depois = outra palavra ("envio" != "env").
        return !Character.isLetterOrDigit(seguinte);
    }

    private Sonda sondar(String url) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .GET()
                    .timeout(Duration.ofSeconds(6))
                    .header("User-Agent", ScannerHttp.USER_AGENT)
                    .build();
            HttpResponse<String> resp = client.send(req, ScannerHttp.limitedString());
            String corpo = resp.body() == null ? "" : resp.body();
            return new Sonda(resp.statusCode(), corpo.length());
        } catch (Exception e) {
            return null;
        }
    }

    private String origemDe(String baseUrl) {
        try {
            URI uri = URI.create(baseUrl);
            return uri.getScheme() + "://" + uri.getHost()
                    + (uri.getPort() > 0 ? ":" + uri.getPort() : "");
        } catch (Exception e) {
            return baseUrl;
        }
    }

    private String fetchRobots(String url) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .GET()
                    .timeout(Duration.ofSeconds(8))
                    .header("User-Agent", ScannerHttp.USER_AGENT)
                    .build();
            HttpResponse<String> resp = ScannerHttp.sendFollowingSafely(client, req, ScannerHttp.limitedString());
            if (resp.statusCode() != 200) return null;

            String body = resp.body();
            String contentType = resp.headers().firstValue("content-type").orElse("");

            return looksLikeRobotsTxt(body, contentType) ? body : null;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Hospedagem de SPA (Cloudflare Pages, Netlify, Vercel) responde o
     * index.html com HTTP 200 para qualquer caminho pedido. Aceitar isso como
     * robots.txt fazia o parser não achar nenhum `Disallow:` no HTML e concluir
     * "sem exposições" — laudo verde para um arquivo que não existe.
     *
     * Content-Type resolve o caso limpo, mas há servidor legítimo que serve
     * robots.txt como octet-stream, então quando o cabeçalho não confirma
     * exigimos ao menos uma diretiva reconhecida no corpo.
     */
    private boolean looksLikeRobotsTxt(String body, String contentType) {
        if (body == null) return false;

        String trimmed = body.trim();
        if (trimmed.startsWith("<")) return false;   // HTML/XML nunca é robots.txt

        if (contentType.toLowerCase(Locale.ROOT).startsWith("text/plain")) return true;

        String lower = trimmed.toLowerCase(Locale.ROOT);
        return ROBOTS_DIRECTIVES.stream().anyMatch(lower::contains);
    }
}
