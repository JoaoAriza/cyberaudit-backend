package com.joao.cyberaudit.service;

import com.joao.cyberaudit.service.DnsSecurityService.ProvedorDeEmail;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * O palpite dirigido de DKIM.
 *
 * O seletor DKIM é um nome arbitrário e não tem como ser descoberto — só adivinhado.
 * A sonda antiga adivinhava às cegas: ~40 seletores em 2 domínios, mais de 80 consultas
 * especulativas por scan. O SPF e o MX, que já foram consultados, dizem QUEM entrega o
 * e-mail do domínio; com isso o palpite passa a ser dirigido.
 *
 * Aqui se testa a tabela — a única parte com regra de negócio. O resto é consulta DNS,
 * que não cabe em teste sem rede.
 */
class DkimProviderHintTest {

    private List<String> seletores(String evidencia) {
        return DnsSecurityService.provedoresParaEvidencia(evidencia).stream()
                .flatMap(p -> p.seletores().stream())
                .distinct()
                .toList();
    }

    private List<String> nomes(String evidencia) {
        return DnsSecurityService.provedoresParaEvidencia(evidencia).stream()
                .map(ProvedorDeEmail::nome)
                .toList();
    }

    // ── O ganho ──────────────────────────────────────────────────────────────

    @Test
    @DisplayName("SPF do Google entrega o seletor do Google — 1 palpite em vez de 40")
    void spfRevelaGoogle() {
        var s = seletores("v=spf1 include:_spf.google.com ~all");

        assertEquals(List.of("google"), s);
    }

    @Test
    @DisplayName("MX também revela o provedor — domínio que só recebe não fica sem pista")
    void mxRevelaProvedor() {
        // Domínio sem SPF ainda pode ter DKIM. Ficar só no SPF perderia esse caso.
        var s = seletores("10 aspmx.l.google.com. 20 alt1.aspmx.l.google.com.");

        assertEquals(List.of("google"), s);
    }

    @Test
    @DisplayName("Microsoft 365 pelo destino do MX")
    void mxDaMicrosoft() {
        var s = seletores("0 contoso-com.mail.protection.outlook.com.");

        assertTrue(s.containsAll(List.of("selector1", "selector2")), "veio: " + s);
    }

    // ── O caso comum de verdade ──────────────────────────────────────────────

    @Test
    @DisplayName("recebe no Google e envia pelo SendGrid — os dois entram, não só o primeiro")
    void doisProvedoresNoMesmoSpf() {
        // Parar no primeiro que bate perderia metade dos seletores certos, e é
        // justamente este arranjo (caixa num provedor, transacional em outro) que
        // aparece na maioria dos domínios comerciais.
        var s = seletores("v=spf1 include:_spf.google.com include:sendgrid.net ~all");

        assertTrue(s.contains("google"), "faltou o provedor de recebimento: " + s);
        assertTrue(s.contains("s1"),     "faltou o provedor de envio: " + s);
    }

    @Test
    @DisplayName("SPF só com amazonses tenta resend também — é o caso do cyberauditapp.com")
    void amazonSesSozinhoAindaTentaResend() {
        // Conferido no DNS real: o cyberauditapp.com publica exatamente este SPF e tem
        // o DKIM em `resend._domainkey`. O Resend entrega pela infra da AWS e não põe
        // nome próprio no SPF, então casar só "Amazon SES" faria a rodada dirigida
        // errar justamente no domínio do produto — e cair na força bruta.
        var s = seletores("v=spf1 include:amazonses.com -all");

        assertTrue(s.contains("resend"),    "o DKIM do produto está em resend._domainkey: " + s);
        assertTrue(s.contains("amazonses"), "veio: " + s);
        assertEquals(2, s.size(), "dois palpites bastam para este SPF: " + s);

        var nomes = nomes("v=spf1 include:amazonses.com -all");
        assertTrue(nomes.containsAll(List.of("Resend", "Amazon SES")), "veio: " + nomes);
    }

    // ── Quando não há pista ──────────────────────────────────────────────────

    @Test
    @DisplayName("provedor desconhecido não devolve palpite — cai na lista inteira")
    void provedorDesconhecidoNaoInventa() {
        // Devolver algo aqui faria a sonda gastar a rodada dirigida com seletores sem
        // relação nenhuma com o domínio, e ainda atrasaria a rodada de reserva.
        assertTrue(seletores("v=spf1 ip4:203.0.113.0/24 -all").isEmpty());
    }

    @Test
    @DisplayName("domínio sem SPF e sem MX não produz pista")
    void semEvidenciaNaoProduzPista() {
        assertTrue(seletores("").isEmpty());
        assertTrue(seletores("   ").isEmpty());
        assertTrue(seletores(null).isEmpty());
    }

    @Test
    @DisplayName("o casamento ignora caixa — MX volta com maiúsculas em alguns resolvedores")
    void casamentoIgnoraCaixa() {
        assertFalse(seletores("10 ASPMX.L.GOOGLE.COM.").isEmpty());
    }

    // ── Coerência com a lista de força bruta ─────────────────────────────────

    @Test
    @DisplayName("todo seletor dirigido também está na lista de reserva")
    void seletoresDirigidosSaoSubconjuntoDaListaCompleta() {
        // A rodada de reserva subtrai o que a dirigida já testou. Se um seletor
        // dirigido não estivesse na lista completa, um domínio sem provedor
        // reconhecido nunca o alcançaria — a mudança PERDERIA cobertura em vez de
        // ganhar velocidade.
        @SuppressWarnings("unchecked")
        List<String> completa = (List<String>) org.springframework.test.util.ReflectionTestUtils
                .getField(DnsSecurityService.class, "DKIM_SELECTORS");

        var todos = DnsSecurityService.provedoresParaEvidencia(
                        "amazonses.com resend.com _spf.google.com sendgrid.net "
                      + "mail.protection.outlook.com spf.mandrillapp.com mailgun.org "
                      + "spf.mtasv.net messagingengine.com protonmail.ch zoho.com "
                      + "hubspotemail.net mailjet.com sparkpostmail.com brevo.com "
                      + "convertkit.com createsend.com activecampaign.com ovh.net")
                .stream().flatMap(p -> p.seletores().stream()).distinct().toList();

        assertFalse(todos.isEmpty(), "a evidência acima deveria casar com a tabela inteira");
        for (String s : todos) {
            assertTrue(completa.contains(s),
                    "seletor '" + s + "' é dirigido mas não está em DKIM_SELECTORS — "
                            + "a rodada de reserva nunca o alcançaria");
        }
    }
}
