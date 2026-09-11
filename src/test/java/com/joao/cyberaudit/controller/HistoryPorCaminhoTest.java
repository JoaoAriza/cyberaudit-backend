package com.joao.cyberaudit.controller;

import com.joao.cyberaudit.model.*;
import com.joao.cyberaudit.repository.AppUserRepository;
import com.joao.cyberaudit.service.ScanEntitlementService;
import com.joao.cyberaudit.service.ScanHistoryService;
import com.joao.cyberaudit.service.UserTimeZoneService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * O grafico de score de um caminho so pode ver scans daquele caminho.
 *
 * O que motivou: o botao "Grafico de score" do /solucoes/cartao-private-label
 * (score 0) abria o grafico do dominio inteiro, cujo ponto mais recente era a
 * home (score 8). E o intraday nem olhava o caminho — o filtro so existia no
 * ramo sem data.
 */
class HistoryPorCaminhoTest {

    private final ScanHistoryService history = mock(ScanHistoryService.class);
    private final HistoryController controller = new HistoryController(
            history, mock(ScanEntitlementService.class),
            new UserTimeZoneService(mock(AppUserRepository.class)));

    private final AppUser caller = new AppUser();

    HistoryPorCaminhoTest() {
        caller.setAccount(Account.builder().id(UUID.randomUUID()).build());
    }

    private ScanSummary scan(String url, int score) {
        return new ScanSummary(UUID.randomUUID(), url, "sgsistemas.com.br",
                LocalDateTime.now(), true, score, RiskLevel.CRITICAL, ScanOrigin.MANUAL);
    }

    private final List<ScanSummary> misturados = List.of(
            scan("https://sgsistemas.com.br/", 8),
            scan("https://sgsistemas.com.br/solucoes/cartao-private-label", 0));

    @Test
    @DisplayName("com caminho, o historico traz so aquela pagina")
    void historicoFiltrado() {
        when(history.findByHost(any(), eq("sgsistemas.com.br"), anyInt(), any())).thenReturn(misturados);

        List<ScanSummary> r = controller.byHost(caller, "sgsistemas.com.br",
                null, null, null, "/solucoes/cartao-private-label");

        assertEquals(1, r.size());
        assertEquals(0, r.get(0).getScore());
    }

    @Test
    @DisplayName("o intraday tambem filtra pelo caminho")
    void intradayFiltrado() {
        when(history.findByHostBetween(any(), eq("sgsistemas.com.br"), any(), any())).thenReturn(misturados);

        List<ScanSummary> r = controller.byHost(caller, "sgsistemas.com.br",
                null, "2026-09-07", "2026-09-07", "/");

        assertEquals(1, r.size());
        assertEquals(8, r.get(0).getScore());
    }

    @Test
    @DisplayName("com caminho, a janela e maior antes de filtrar")
    void janelaMaior() {
        when(history.findByHost(any(), any(), anyInt(), any())).thenReturn(List.of());

        controller.byHost(caller, "sgsistemas.com.br", null, null, null, "/login");
        verify(history).findByHost(any(), eq("sgsistemas.com.br"), eq(300), any());

        controller.byHost(caller, "sgsistemas.com.br", null, null, null, null);
        verify(history).findByHost(any(), eq("sgsistemas.com.br"), eq(50), any());
    }

    @Test
    @DisplayName("sem caminho, continua devolvendo o dominio inteiro")
    void semCaminho() {
        when(history.findByHost(any(), any(), anyInt(), any())).thenReturn(misturados);

        assertEquals(2, controller.byHost(caller, "sgsistemas.com.br", null, null, null, null).size());
    }
}
