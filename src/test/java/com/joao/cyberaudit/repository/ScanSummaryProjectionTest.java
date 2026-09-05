package com.joao.cyberaudit.repository;

import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.AccountType;
import com.joao.cyberaudit.model.Plan;
import com.joao.cyberaudit.model.RiskLevel;
import com.joao.cyberaudit.model.ScanOrigin;
import com.joao.cyberaudit.model.ScanRecord;
import com.joao.cyberaudit.model.ScanSummary;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.data.domain.PageRequest;
import org.springframework.test.context.ActiveProfiles;

import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * As projeções de listagem do histórico.
 *
 * Existem porque o laudo inteiro de um scan mora em {@code result_json}, e as
 * listagens devolviam a entidade — arrastando um laudo completo por linha só para
 * desenhar host, data e score. Numa instância pequena de Postgres é o que começa a
 * doer primeiro conforme o histórico cresce.
 *
 * <p>O teste roda as consultas de verdade, e essa é a razão de ele existir: o
 * {@code SELECT new com.joao...ScanSummary(...)} é uma STRING. Nome de classe
 * errado, campo fora de ordem ou construtor com assinatura diferente compilam sem
 * reclamar e explodem na primeira chamada, em produção.
 */
@DataJpaTest
@ActiveProfiles("test")
class ScanSummaryProjectionTest {

    @Autowired ScanRecordRepository repository;
    @Autowired EntityManager em;

    private Account conta;
    private Account outraConta;

    private static final PageRequest PAGINA = PageRequest.of(0, 50);

    @BeforeEach
    void semeia() {
        conta      = persisteConta("dona@exemplo.test");
        outraConta = persisteConta("vizinha@exemplo.test");

        persiste("exemplo.test", conta,      70, ScanOrigin.MANUAL,    true,  horasAtras(1));
        persiste("exemplo.test", conta,      55, ScanOrigin.SCHEDULED, false, horasAtras(3));
        persiste("outro.test",   conta,      90, ScanOrigin.MANUAL,    false, horasAtras(2));
        persiste("exemplo.test", outraConta, 10, ScanOrigin.MANUAL,    false, horasAtras(1));
        em.flush();
        em.clear();
    }

    // ── As consultas resolvem ────────────────────────────────────────────────

    @Test
    @DisplayName("toda projeção nova executa e devolve os campos do resumo")
    void todasAsProjecoesResolvem() {
        // Sete strings de JPQL. Uma chamada de cada é o que separa "compila" de
        // "funciona" — e o custo de descobrir isso em produção é uma tela quebrada.
        assertFalse(repository.findSummariesByAccount(conta, PAGINA).isEmpty());
        assertFalse(repository.findSummariesByAccountAndOrigin(
                conta, ScanOrigin.MANUAL, PAGINA).isEmpty());
        assertFalse(repository.findSummariesByAccountAndHost(
                conta, "exemplo.test", PAGINA).isEmpty());
        assertFalse(repository.findSummariesByAccountAndHostAndOrigin(
                conta, "exemplo.test", ScanOrigin.SCHEDULED, PAGINA).isEmpty());
        assertFalse(repository.findSummariesByAccountAndHostBetween(
                conta, "exemplo.test", horasAtras(24), LocalDateTime.now(), PAGINA).isEmpty());
        assertFalse(repository.findSummariesByHost("exemplo.test", PAGINA).isEmpty());
        assertFalse(repository.findLatestSummaryPerHostByAccount(conta, PAGINA).isEmpty());
    }

    @Test
    @DisplayName("o resumo carrega os oito campos que a tela usa")
    void camposChegamPreenchidos() {
        ScanSummary s = repository.findSummariesByAccountAndHost(
                conta, "exemplo.test", PageRequest.of(0, 1)).get(0);

        assertEquals("exemplo.test", s.getHost());
        assertEquals("https://exemplo.test", s.getUrl());
        assertEquals(70, s.getScore());                       // o mais recente
        assertEquals(RiskLevel.MEDIUM, s.getRiskLevel());
        assertEquals(ScanOrigin.MANUAL, s.getOrigin());
        assertTrue(s.isActiveMode());
        assertTrue(s.getId() != null);
        assertTrue(s.getScannedAt() != null);
    }

    // ── O que a projeção não pode perder ─────────────────────────────────────

    @Test
    @DisplayName("a ordenação por data continua sendo a do mais recente primeiro")
    void ordemPreservada() {
        List<ScanSummary> lista = repository.findSummariesByAccountAndHost(
                conta, "exemplo.test", PAGINA);

        assertEquals(2, lista.size());
        assertTrue(lista.get(0).getScannedAt().isAfter(lista.get(1).getScannedAt()));
    }

    @Test
    @DisplayName("o escopo de conta sobrevive — listagem não vaza scan do vizinho")
    void escopoDeContaPreservado() {
        // A projeção reescreveu o WHERE à mão. Perder o filtro de conta aqui
        // devolveria o histórico de outro tenant, que é o pior erro possível.
        List<ScanSummary> lista = repository.findSummariesByAccountAndHost(
                conta, "exemplo.test", PAGINA);

        assertEquals(2, lista.size());
        assertTrue(lista.stream().noneMatch(s -> s.getScore() == 10),
                "apareceu o scan da outra conta na listagem");
    }

    @Test
    @DisplayName("o filtro de origin continua separando manual de agendado")
    void filtroDeOrigem() {
        assertEquals(1, repository.findSummariesByAccountAndHostAndOrigin(
                conta, "exemplo.test", ScanOrigin.SCHEDULED, PAGINA).size());
        assertEquals(1, repository.findSummariesByAccountAndHostAndOrigin(
                conta, "exemplo.test", ScanOrigin.MANUAL, PAGINA).size());
    }

    @Test
    @DisplayName("último por host devolve um por host, o mais recente de cada")
    void ultimoPorHost() {
        List<ScanSummary> lista = repository.findLatestSummaryPerHostByAccount(conta, PAGINA);

        assertEquals(2, lista.size(), "dois hosts distintos na conta");
        assertTrue(lista.stream().anyMatch(s -> s.getHost().equals("exemplo.test") && s.getScore() == 70));
        assertTrue(lista.stream().anyMatch(s -> s.getHost().equals("outro.test")));
    }

    @Test
    @DisplayName("origem nula de registro legado vira MANUAL, não null")
    void origemLegadaNormaliza() {
        // A coluna origin nasceu depois dos primeiros scans. O default vivia no
        // ScanSummary.from; a projeção não passa por lá, então ele desceu para o
        // construtor — que é por onde os dois caminhos agora entram.
        persiste("legado.test", conta, 40, null, false, horasAtras(1));
        em.flush();
        em.clear();

        ScanSummary s = repository.findSummariesByAccountAndHost(
                conta, "legado.test", PAGINA).get(0);

        assertEquals(ScanOrigin.MANUAL, s.getOrigin());
    }

    // ── Semeadura ────────────────────────────────────────────────────────────

    private LocalDateTime horasAtras(int horas) {
        return LocalDateTime.now().minusHours(horas);
    }

    private Account persisteConta(String email) {
        Account a = new Account();
        a.setDisplayName(email);
        a.setPlan(Plan.FREE);
        a.setType(AccountType.INDIVIDUAL);
        a.setCreatedAt(LocalDateTime.now());
        em.persist(a);
        return a;
    }

    private void persiste(String host, Account account, int score, ScanOrigin origin,
                          boolean activeMode, LocalDateTime quando) {
        em.persist(ScanRecord.builder()
                .url("https://" + host)
                .host(host)
                .scannedAt(quando)
                .activeMode(activeMode)
                .score(score)
                .riskLevel(RiskLevel.MEDIUM)
                // O blob que a projeção existe para não carregar.
                .resultJson("{\"url\":\"https://" + host + "\",\"filler\":\""
                        + "x".repeat(2000) + "\"}")
                .account(account)
                .origin(origin)
                .build());
    }
}
