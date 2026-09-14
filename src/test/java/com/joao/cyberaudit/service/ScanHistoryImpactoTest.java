package com.joao.cyberaudit.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.joao.cyberaudit.dto.PathSummaryDto;
import com.joao.cyberaudit.model.*;
import com.joao.cyberaudit.repository.ScanRecordRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * O rótulo de impacto atravessa o histórico: do laudo para a linha gravada, e da
 * linha para o card de cada caminho.
 *
 * Sem a cópia na gravação, a aba Caminhos teria de abrir o laudo inteiro de cada
 * página só para mostrar uma palavra — exatamente o custo que a projeção existe
 * para evitar.
 */
class ScanHistoryImpactoTest {

    private final ScanRecordRepository repository = mock(ScanRecordRepository.class);
    private final ScanHistoryService   service    = new ScanHistoryService(repository, new ObjectMapper());

    @Test
    @DisplayName("gravar o scan copia o impacto do laudo para a coluna")
    void gravacaoCopiaImpacto() {
        ScanResult r = ScanResult.builder()
                .url("https://loja.test/checkout")
                .score(new ScoreResult(30, RiskLevel.HIGH, List.of(), List.of()))
                .impact(ImpactLevel.PAYMENT)
                .build();

        service.save(r, Account.builder().id(UUID.randomUUID()).build(), ScanOrigin.MANUAL);

        ArgumentCaptor<ScanRecord> gravado = ArgumentCaptor.forClass(ScanRecord.class);
        verify(repository).save(gravado.capture());
        assertEquals(ImpactLevel.PAYMENT, gravado.getValue().getImpact());
    }

    @Test
    @DisplayName("cada caminho leva o próprio impacto: home VITRINE, checkout PAGAMENTO")
    void caminhoLevaOProprioImpacto() {
        Account conta = Account.builder().id(UUID.randomUUID()).build();
        when(repository.findSummariesByAccount(eq(conta), any())).thenReturn(List.of(
                resumo("https://loja.test/checkout", ImpactLevel.PAYMENT),
                resumo("https://loja.test/", ImpactLevel.SHOWCASE)));

        List<PathSummaryDto> caminhos = service.findLatestPerPath(conta, 50);

        assertEquals(ImpactLevel.PAYMENT,  porCaminho(caminhos, "/checkout").impact());
        assertEquals(ImpactLevel.SHOWCASE, porCaminho(caminhos, "/").impact());
    }

    private ScanSummary resumo(String url, ImpactLevel impact) {
        return new ScanSummary(UUID.randomUUID(), url, "loja.test", LocalDateTime.now(),
                false, 40, RiskLevel.HIGH, ScanOrigin.MANUAL, impact);
    }

    private PathSummaryDto porCaminho(List<PathSummaryDto> lista, String path) {
        return lista.stream().filter(p -> p.path().equals(path)).findFirst().orElseThrow();
    }
}
