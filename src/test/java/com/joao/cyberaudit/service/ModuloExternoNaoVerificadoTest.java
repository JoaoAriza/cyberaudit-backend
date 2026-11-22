package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.CertTransparencyResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Módulo que depende de serviço externo só marca "OK" quando o serviço respondeu.
 *
 * Parte da regressão do BUG-16 (cyberaudit-qa). O módulo marcava "OK" sempre que
 * terminava a tempo, e a falha do NVD ou dos logs de Certificate Transparency terminava
 * a tempo, como lista vazia. O laudo dizia "sem CVE" e "sem certificados" sem ter
 * conferido. Decisão do dono (2026-11-22): marcar "ERROR", que entra no aviso de
 * resultado parcial.
 */
class ModuloExternoNaoVerificadoTest {

    private static <T> String estado(T valor, java.util.function.Predicate<T> respondeu) {
        return ScanOrchestrator.moduleStateVerificado(CompletableFuture.completedFuture(valor), respondeu);
    }

    // ── O estado do módulo ──────────────────────────────────────────────────

    @Test
    @DisplayName("CVE: NVD respondeu tudo é OK; alguma consulta falhou é ERROR")
    void estadoDoCve() {
        var completa   = new CVECorrelationService.Correlacao(List.of(), true);
        var incompleta = new CVECorrelationService.Correlacao(List.of(), false);

        assertEquals("OK",    estado(completa,   ScanOrchestrator.CVE_RESPONDEU));
        assertEquals("ERROR", estado(incompleta, ScanOrchestrator.CVE_RESPONDEU));
        assertEquals("ERROR", estado(null,       ScanOrchestrator.CVE_RESPONDEU),
                "null é exceção no caminho (o future trocou a exceção por null)");
    }

    @Test
    @DisplayName("CT: resultado (mesmo sem certificado) é OK; nenhuma fonte respondeu é ERROR")
    void estadoDoCt() {
        assertEquals("OK",    estado(CertTransparencyResult.builder().build(), ScanOrchestrator.CT_RESPONDEU));
        assertEquals("ERROR", estado(null, ScanOrchestrator.CT_RESPONDEU));
    }

    @Test
    @DisplayName("não terminou a tempo continua TIMEOUT, como nos outros módulos")
    void naoTerminouETimeout() {
        assertEquals("TIMEOUT", ScanOrchestrator.moduleStateVerificado(
                new CompletableFuture<CertTransparencyResult>(), ScanOrchestrator.CT_RESPONDEU));
    }

    // ── O CT devolve null quando nenhuma fonte respondeu ────────────────────

    @Test
    @DisplayName("CT: crt.sh e certspotter fora do ar dá null, e não um resultado vazio")
    void ctSemFonteDevolveNull() {
        CrtShService fontes = mock(CrtShService.class);
        when(fontes.fetchCertsOuNull("exemplo.test")).thenReturn(null);

        assertNull(new CertTransparencyService(fontes).scan("exemplo.test", null));
    }

    @Test
    @DisplayName("controle: CT consultado e sem certificado é resultado vazio, não null")
    void ctSemCertificadoEResultado() {
        CrtShService fontes = mock(CrtShService.class);
        when(fontes.fetchCertsOuNull("exemplo.test")).thenReturn(List.of());

        assertNotNull(new CertTransparencyService(fontes).scan("exemplo.test", null));
    }
}
