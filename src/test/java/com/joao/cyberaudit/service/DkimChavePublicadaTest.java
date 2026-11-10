package com.joao.cyberaudit.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * O que conta como "DKIM encontrado" num seletor (BUG-09).
 *
 * A sonda contava qualquer TXT no nome {@code seletor._domainkey.dominio}. Dois casos
 * reais mostram por que não basta:
 *
 * - A Hostinger publica três seletores, {@code hostingermail-a/-b/-c}, e só o {@code -a}
 *   tem chave: {@code -b} e {@code -c} são {@code v=DKIM1;p=} — chave REVOGADA, o jeito
 *   que a RFC 6376 §3.6.1 dá para desligar um seletor. Conferido no DNS de um domínio de
 *   cliente em 2026-11-09. Contar esses como encontrados afirmaria uma assinatura que
 *   nenhum receptor aceita.
 * - Domínio com TXT curinga ({@code *.dominio TXT "v=spf1 ..."}) faz TODO seletor
 *   "existir". A mesma seção manda descartar registro cujo {@code v=} não é
 *   {@code DKIM1}.
 *
 * Os textos já chegam com as partes do TXT juntadas — é o que a sonda entrega.
 */
class DkimChavePublicadaTest {

    /** O -a da Hostinger, encurtado: a chave em uso. */
    private static final String CHAVE_HOSTINGER =
            "v=DKIM1;k=rsa;p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs+R";

    private static boolean temChave(String... textos) {
        return DnsSecurityService.temChaveDkim(List.of(textos));
    }

    @Test
    @DisplayName("chave publicada conta")
    void chavePublicada() {
        assertTrue(temChave(CHAVE_HOSTINGER));
    }

    @ParameterizedTest(name = "revogada: \"{0}\"")
    @ValueSource(strings = {
            "v=DKIM1;p=",              // o -b e o -c da Hostinger, como estão no DNS
            "v=DKIM1; k=rsa; p=",
            "v=DKIM1; k=rsa; p= ",
            "v=DKIM1; p=; t=s"
    })
    @DisplayName("chave revogada (p= vazio) não conta")
    void chaveRevogadaNaoConta(String registro) {
        assertFalse(temChave(registro));
    }

    @Test
    @DisplayName("sem v= continua valendo — a tag é opcional")
    void semVersaoContinuaValendo() {
        assertTrue(temChave("k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC"));
    }

    @Test
    @DisplayName("espaço dentro do p= não invalida a chave")
    void espacoDentroDaChave() {
        // A RFC permite espaço em branco no meio do valor; quem publica à mão às vezes
        // quebra a chave assim.
        assertTrue(temChave("v=DKIM1; k=rsa; p=MIGfMA0G CSqGSIb3 DQEBAQUA"));
    }

    @ParameterizedTest(name = "não é chave: \"{0}\"")
    @ValueSource(strings = {
            "v=spf1 include:_spf.mail.hostinger.com ~all",   // TXT curinga do domínio
            "google-site-verification=abc123",
            "v=DKIM2; p=MIGfMA0GCSqGSIb3"                     // v= que não é DKIM1
    })
    @DisplayName("TXT que não é chave DKIM não conta")
    void txtQueNaoEChave(String registro) {
        assertFalse(temChave(registro));
    }

    @Test
    @DisplayName("um TXT revogado ao lado de uma chave válida: conta pela válida")
    void revogadaAoLadoDeValida() {
        assertTrue(temChave("v=DKIM1;p=", CHAVE_HOSTINGER));
    }

    @Test
    @DisplayName("nenhum TXT não conta")
    void nenhumTxt() {
        assertFalse(DnsSecurityService.temChaveDkim(List.of()));
        assertFalse(DnsSecurityService.temChaveDkim(null));
    }
}
