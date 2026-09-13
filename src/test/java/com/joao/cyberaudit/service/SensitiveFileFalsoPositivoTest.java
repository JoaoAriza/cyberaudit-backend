package com.joao.cyberaudit.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * O detector de arquivos sensíveis só pode reportar TEXTO legível.
 *
 * Dois casos reais, um de cada lado:
 *
 *  - revestacabamentos.com.br: reportou .env, .env.local, .env.production,
 *    .env.backup e wp-config.php.bak com preview binário IDÊNTICO — o servidor
 *    respondia o mesmo blob comprimido/opaco para qualquer path (catch-all), e os
 *    bytes casaram com a regra frouxa "[A-Z_]+=.+" do .env. Falso positivo.
 *
 *  - frrodas.com.br: .env de verdade exposto em produção, texto legível com
 *    cabeçalho em comentário e credenciais. Tem de continuar sendo reportado — foi
 *    a razão de o ajuste ser cauteloso.
 */
class SensitiveFileFalsoPositivoTest {

    private final SensitiveFileService service = new SensitiveFileService();

    /**
     * Blob binário: U+FFFD (byte que não decodificou como UTF-8) e controles C0,
     * intercalados com uns poucos imprimíveis — inclusive "APP_" e "X=", que a
     * regra antiga do .env exigia. Montado por código, não por bytes crus no fonte,
     * para o teste não depender da codificação do arquivo.
     */
    private String blobBinario() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 40; i++) {
            sb.append('�');            // caractere-substituto
            sb.append((char) (i % 7 + 1));  // controle C0 (0x01..0x07)
            if (i == 10) sb.append("X=");
            if (i == 20) sb.append("APP_");
        }
        return sb.toString();
    }

    /** .env real (frrodas): comentário no topo, depois pares CHAVE=valor. */
    private String envReal() {
        return "# =================================================\n"
             + "# JIREH SaaS — Variáveis de Ambiente\n"
             + "# =================================================\n"
             + "APP_NAME=Jireh\n"
             + "APP_ENV=production\n"
             + "DB_HOST=127.0.0.1\n"
             + "DB_PASSWORD=Sup3rS3cr3t!\n"
             + "API_KEY=sk_live_abcdef123456\n";
    }

    @Test
    @DisplayName("blob binario servido como .env NAO e reportado, mesmo casando a regra antiga")
    void blobBinarioNaoReportado() {
        assertFalse(service.isRealContent("/.env", blobBinario(), "application/octet-stream"),
                "conteudo binario nao pode virar finding de .env");
        assertFalse(service.isRealContent("/wp-config.php.bak", blobBinario(), ""),
                "o mesmo blob no .bak tambem e falso positivo");
    }

    @Test
    @DisplayName(".env real em texto continua sendo reportado")
    void envRealReportado() {
        assertTrue(service.isRealContent("/.env", envReal(), "text/plain"),
                ".env legivel com credenciais tem de ser reportado");
    }

    @Test
    @DisplayName("looksLikeText separa binario de texto, e acento nao conta como binario")
    void gateDeTexto() {
        assertFalse(service.looksLikeText(blobBinario()));
        assertTrue(service.looksLikeText(envReal()));
        // Acento e travessao sao texto legitimo, nao binario.
        assertTrue(service.looksLikeText("# Variáveis de Ambiente — configuração\nDB_USER=root\n"));
    }

    @Test
    @DisplayName("SQL binario nao passa; SQL real passa")
    void sqlContinuaFuncionando() {
        assertFalse(service.isRealContent("/backup.sql", blobBinario(), ""));
        assertTrue(service.isRealContent("/backup.sql",
                "INSERT INTO users (id, email) VALUES (1, 'a@b.com');", "text/plain"));
    }
}
