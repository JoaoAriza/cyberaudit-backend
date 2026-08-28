package com.joao.cyberaudit.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Um marcador forte, ou dois fracos.
 *
 * Varredura feita depois de o cliente achar os falsos positivos do github.com. Os
 * módulos que restavam foram revistos com o mesmo critério: <b>o que confirma o
 * achado prova o comportamento, ou só prova que a palavra apareceu?</b>
 *
 * <ul>
 *   <li><b>Open Redirect</b> — correto. Exige 3xx E o HOST do Location ser o probe,
 *       com anti-FP explícito para o {@code continue=} do OAuth. Não mexi;</li>
 *   <li><b>HTTP Methods</b> — correto. Recusa 404/400/3xx/5xx e 200+HTML (a página
 *       padrão da SPA), e rebaixa o que exige autenticação. Não mexi;</li>
 *   <li><b>SSRF</b> — o pior. Um marcador bastava para CRITICAL, e vários casam por
 *       substring em texto comum;</li>
 *   <li><b>Directory Listing</b> — frase solta confirmava listagem exposta;</li>
 *   <li><b>Path Traversal</b> — só o {@code /etc/hosts}, por um par frágil.</li>
 * </ul>
 */
class MarkerStrengthTest {

    // ── SSRF ─────────────────────────────────────────────────────────────────

    private String ssrfAws(String corpo) {
        var s = new SsrfService();
        return s.confirma(corpo, corpo.toLowerCase(),
                List.of("security-credentials", "local-ipv4", "public-hostname",
                        "ami-launch-index", "instance-identity", "iam/info"),
                List.of("ami-", "instance-id", "placement/", "meta-data", "instance-type"));
    }

    @Test
    @DisplayName("um marcador fraco sozinho não vira SSRF CRITICAL")
    void marcadorFracoSozinhoNaoConfirma() {
        // "ami-" casa dentro de "Miami-Dade"; "placement/" com uma rota de ad-tech;
        // "meta-data" com um atributo qualquer. Cada um valia CRITICAL sozinho.
        assertNull(ssrfAws("<p>Nossa sede fica em Miami-Dade County</p>"));
        assertNull(ssrfAws("<a href=\"/ad-placement/policy\">Regras</a>"));
        assertNull(ssrfAws("<div data-meta-data=\"x\">conteudo</div>"));
    }

    @Test
    @DisplayName("dois marcadores fracos juntos confirmam — coincidência dupla é evidência")
    void doisFracosConfirmam() {
        assertNotNull(ssrfAws("instance-id: i-0abc\ninstance-type: t3.micro"));
    }

    @Test
    @DisplayName("um marcador forte confirma sozinho — só existe no IMDS")
    void forteConfirmaSozinho() {
        assertNotNull(ssrfAws("iam/security-credentials/role-app"));
        assertNotNull(ssrfAws("local-ipv4"));
    }

    @Test
    @DisplayName("a resposta real do IMDS continua sendo detectada")
    void imdsRealContinuaDetectado() {
        // Saída de /latest/meta-data/ — a lista de chaves que o serviço devolve.
        assertNotNull(ssrfAws("""
                ami-id
                ami-launch-index
                hostname
                instance-id
                instance-type
                local-ipv4
                public-hostname
                """));
    }

    // ── Directory Listing ────────────────────────────────────────────────────

    private String listagem(String html) {
        return new DirectoryListingService().findSignature(html.toLowerCase());
    }

    @Test
    @DisplayName("página que FALA de directory listing não é uma listagem exposta")
    void artigoSobreListagemNaoEAchado() {
        assertNull(listagem("""
                <html><head><title>Como desativar directory listing no Apache</title></head>
                <body><p>O directory listing expõe seus arquivos. Desative com Options -Indexes.</p>
                </body></html>
                """));
    }

    @Test
    @DisplayName("índice de blog com 'last modified' não é listagem de diretório")
    void indiceDeBlogNaoEAchado() {
        assertNull(listagem("<ul><li><a href='/post'>Post</a> <a>Last modified</a></li></ul>"));
    }

    @Test
    @DisplayName("autoindex de verdade continua sendo detectado")
    void autoindexRealViraAchado() {
        assertNotNull(listagem("<html><head><title>Index of /uploads</title></head><body>"));
        assertNotNull(listagem("<h1>Index of /backup</h1><pre><a href=\"../\">Parent Directory</a>"));
        assertNotNull(listagem("<A HREF=\"/files/\">[To Parent Directory]</A>".toLowerCase()));
    }

    // ── Path Traversal ───────────────────────────────────────────────────────

    private String traversal(String corpo, String alvo) {
        return new PathTraversalService().matchesFileContent(corpo, alvo);
    }

    @Test
    @DisplayName("tutorial que cita 127.0.0.1 e localhost não é /etc/hosts vazado")
    void tutorialDeRedeNaoELfi() {
        // O par solto acusava LFI CRITICAL em qualquer página de documentação que
        // mencionasse os dois em pontos diferentes do texto.
        assertNull(traversal(
                "<p>Use o endereço 127.0.0.1 para acessar o servidor.</p>"
                        + "<p>Também funciona pelo nome localhost.</p>", "/etc/hosts"));
    }

    @Test
    @DisplayName("/etc/hosts servido de verdade continua sendo detectado")
    void hostsRealViraAchado() {
        assertNotNull(traversal("127.0.0.1\tlocalhost\n::1\tip6-localhost\n", "/etc/hosts"));
        assertNotNull(traversal("127.0.0.1   localhost.localdomain localhost", "/etc/hosts"));
    }

    @Test
    @DisplayName("/etc/passwd continua exigindo dupla evidência")
    void passwdMantemDuplaEvidencia() {
        assertNotNull(traversal("root:x:0:0:root:/root:/bin/bash", "/etc/passwd"));
        // "root:" sozinho, sem o /bin/, não confirma.
        assertNull(traversal("<p>Faça login como root: use o painel.</p>", "/etc/passwd"));
    }
}
