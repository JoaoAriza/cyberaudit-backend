package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.PortFinding;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * A penalidade de portas, com a suavização para hospedagem compartilhada.
 *
 * Em hospedagem (cPanel), o pacote padrão — SSH, DNS, e-mail — deixa de descontar:
 * é serviço do servidor da hospedagem, que o dono do site não administra. O que é
 * risco real mesmo assim (FTP em texto plano, TELNET, banco exposto) continua
 * pesando. Fora de hospedagem, a regra antiga vale igual.
 */
class ScorePortsTest {

    private PortFinding porta(int p, String sev) {
        PortFinding f = new PortFinding();
        f.setPort(p);
        f.setSeverity(sev);
        f.setState("OPEN");
        return f;
    }

    /** O conjunto real do lelesautomoveis. */
    private List<PortFinding> lelesautomoveis() {
        List<PortFinding> l = new ArrayList<>();
        l.add(porta(21, "HIGH"));      // FTP
        l.add(porta(22, "MEDIUM"));    // SSH
        l.add(porta(53, "LOW"));       // DNS
        l.add(porta(80, "LOW"));       // HTTP
        l.add(porta(110, "LOW"));      // POP3
        l.add(porta(143, "LOW"));      // IMAP
        l.add(porta(443, "INFO"));     // HTTPS
        l.add(porta(993, "LOW"));      // IMAPS
        l.add(porta(995, "LOW"));      // POP3S
        return l;
    }

    @Test
    @DisplayName("hospedagem compartilhada: só o FTP em texto plano pesa (-10), não os -25 de antes")
    void hospedagemSoOFtp() {
        ScoreService.PortScore ps = ScoreService.penalidadePortas(lelesautomoveis());

        assertEquals(10, ps.penalty(), "só o FTP (HIGH) desconta; o pacote da hospedagem não");
        assertEquals(1, ps.riskyCount());
    }

    @Test
    @DisplayName("fora de hospedagem, o mesmo conjunto pesaria o valor cheio (teto 30)")
    void semHospedagemValorCheio() {
        // Sem a pilha de e-mail não casa a assinatura: FTP -10, SSH -5, DNS -2 = -17.
        List<PortFinding> l = new ArrayList<>();
        l.add(porta(21, "HIGH"));
        l.add(porta(22, "MEDIUM"));
        l.add(porta(53, "LOW"));
        l.add(porta(80, "LOW"));   // não conta
        l.add(porta(443, "INFO")); // não conta

        ScoreService.PortScore ps = ScoreService.penalidadePortas(l);
        assertEquals(17, ps.penalty());
        assertEquals(3, ps.riskyCount());
    }

    @Test
    @DisplayName("em hospedagem, banco exposto continua pesando — não é serviço normal do painel")
    void bancoExpostoAindaPesa() {
        List<PortFinding> l = lelesautomoveis();
        l.add(porta(3306, "HIGH"));   // MySQL exposto

        ScoreService.PortScore ps = ScoreService.penalidadePortas(l);
        assertEquals(20, ps.penalty(), "FTP -10 + MySQL -10");
        assertEquals(2, ps.riskyCount());
    }

    @Test
    @DisplayName("teto de 30 é respeitado")
    void teto() {
        List<PortFinding> l = new ArrayList<>();
        for (int p : new int[]{1433, 1521, 3306, 5432}) l.add(porta(p, "HIGH")); // 4 x -10 = 40
        assertEquals(30, ScoreService.penalidadePortas(l).penalty());
    }
}
