package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.PortFinding;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A assinatura de hospedagem compartilhada pelas portas abertas.
 *
 * O caso real (lelesautomoveis.com.br): FTP + SSH + DNS + web + a pilha de e-mail
 * (POP3/IMAP/IMAPS/POP3S) — cara de cPanel. Essas portas são do servidor da
 * hospedagem, não do dono do site, e não devem pesar contra ele no score.
 */
class PortHostingTest {

    private PortFinding porta(int p) {
        PortFinding f = new PortFinding();
        f.setPort(p);
        f.setState("OPEN");
        return f;
    }

    @Test
    @DisplayName("pilha de e-mail (>=2 portas) = hospedagem compartilhada")
    void pilhaDeEmail() {
        // O conjunto do lelesautomoveis.
        List<PortFinding> portas = List.of(
                porta(21), porta(22), porta(53), porta(80),
                porta(110), porta(143), porta(443), porta(993), porta(995));
        assertTrue(PortScanService.pareceHospedagemCompartilhada(portas));
    }

    @Test
    @DisplayName("uma porta de e-mail sozinha não basta")
    void umaSoNaoBasta() {
        assertFalse(PortScanService.pareceHospedagemCompartilhada(List.of(porta(993))));
    }

    @Test
    @DisplayName("servidor de aplicação (só web) não é hospedagem compartilhada")
    void appServerNao() {
        assertFalse(PortScanService.pareceHospedagemCompartilhada(List.of(porta(80), porta(443), porta(22))));
    }

    @Test
    @DisplayName("lista vazia ou nula não quebra")
    void bordas() {
        assertFalse(PortScanService.pareceHospedagemCompartilhada(List.of()));
        assertFalse(PortScanService.pareceHospedagemCompartilhada(null));
    }
}
