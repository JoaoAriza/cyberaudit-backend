package com.joao.cyberaudit.service;

import com.joao.cyberaudit.exception.TargetUnreachableException;
import com.joao.cyberaudit.model.AsyncScanStatus;
import com.joao.cyberaudit.model.ScanOrigin;
import com.joao.cyberaudit.repository.AppUserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.support.ResourceBundleMessageSource;

import java.util.concurrent.CompletionException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * No scan assíncrono, o alvo inacessível chega ao polling como código, não como texto.
 *
 * Parte da regressão do BUG-16 (cyberaudit-qa). A tela da interface usa o
 * {@code /scan/async}: o 422 do alvo sem resposta acontece dentro do scan, numa thread
 * sem resposta HTTP, e o cliente só fica sabendo pelo status. Com {@code errorCode}
 * ({@code TARGET_UNREACHABLE}, {@code TARGET_NOT_FOUND}) e {@code errorHost}, a tela mostra
 * o aviso de domínio inacessível sem procurar palavras na mensagem, como já faz com a
 * posse ({@code OWNERSHIP_REQUIRED}).
 *
 * O {@code BackgroundRunner} sem o proxy do Spring roda a tarefa na mesma thread: o
 * status já está pronto quando o submit volta.
 */
class AsyncScanAlvoInacessivelTest {

    private static final String DONO = "ip:198.51.100.16";

    private final ScanOrchestrator orquestrador = mock(ScanOrchestrator.class);

    private AsyncScanService service() {
        var source = new ResourceBundleMessageSource();
        source.setBasename("messages");
        source.setDefaultEncoding("UTF-8");
        source.setFallbackToSystemLocale(false);
        return new AsyncScanService(orquestrador, mock(EmailService.class),
                mock(AppUserRepository.class), mock(ScanEntitlementService.class),
                new MessageCatalog(source), new BackgroundRunner());
    }

    private AsyncScanStatus statusQuandoOScanLanca(RuntimeException erro) {
        when(orquestrador.execute(anyString(), anyBoolean(), any(), anyBoolean(),
                any(ScanOrigin.class), any(ScanProgress.class))).thenThrow(erro);
        AsyncScanService service = service();
        String scanId = service.submit("http://alvo.test/", false, null, false, false, DONO);
        return service.getStatusFor(scanId, DONO);
    }

    @Test
    @DisplayName("alvo sem resposta: ERROR com TARGET_UNREACHABLE, o host e a mensagem")
    void semRespostaViraCodigo() {
        AsyncScanStatus s = statusQuandoOScanLanca(new TargetUnreachableException(
                TargetUnreachableException.SEM_RESPOSTA, "alvo.test", "O site alvo.test não respondeu."));

        assertEquals(AsyncScanStatus.State.ERROR, s.getState());
        assertEquals("TARGET_UNREACHABLE", s.getErrorCode());
        assertEquals("alvo.test", s.getErrorHost());
        assertEquals("O site alvo.test não respondeu.", s.getErrorMessage());
    }

    @Test
    @DisplayName("domínio que deixou de resolver entre o submit e o scan: TARGET_NOT_FOUND")
    void naoResolveViraCodigo() {
        AsyncScanStatus s = statusQuandoOScanLanca(new TargetUnreachableException(
                TargetUnreachableException.NAO_RESOLVE, "alvo.test", "O domínio alvo.test não foi encontrado."));

        assertEquals("TARGET_NOT_FOUND", s.getErrorCode());
        assertEquals("alvo.test", s.getErrorHost());
    }

    @Test
    @DisplayName("o código é achado mesmo com a exceção embrulhada")
    void achaNaCadeiaDeCausas() {
        AsyncScanStatus s = statusQuandoOScanLanca(new CompletionException(new TargetUnreachableException(
                TargetUnreachableException.SEM_RESPOSTA, "alvo.test", "O site alvo.test não respondeu.")));

        assertEquals("TARGET_UNREACHABLE", s.getErrorCode());
    }

    @Test
    @DisplayName("controle: erro qualquer continua sem código e com a mensagem genérica")
    void outroErroSemCodigo() {
        AsyncScanStatus s = statusQuandoOScanLanca(new IllegalStateException("detalhe interno"));

        assertEquals(AsyncScanStatus.State.ERROR, s.getState());
        assertNull(s.getErrorCode());
        assertEquals("Erro ao executar o scan. Verifique a URL e tente novamente.", s.getErrorMessage());
    }
}
