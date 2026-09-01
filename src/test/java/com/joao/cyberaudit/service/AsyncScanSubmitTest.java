package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.AsyncScanStatus;
import com.joao.cyberaudit.model.ScanOrigin;
import com.joao.cyberaudit.model.ScanResult;
import com.joao.cyberaudit.repository.AppUserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * O {@code /scan/async} devolve o scanId ANTES de o scan terminar.
 *
 * Parece óbvio pelo nome do endpoint, e não era verdade: {@code submit()} chamava
 * o próprio {@code executeAsync()}, anotado com {@code @Async}. Auto-invocação não
 * passa pelo proxy do Spring, então a anotação não fazia nada e o POST executava as
 * 25 verificações antes de responder. O cliente recebia o id de um scan que já tinha
 * acabado.
 *
 * Nada quebrava — a tela mostrava um spinner de qualquer jeito. O defeito só
 * apareceu quando o feed de progresso foi construir algo naquela janela e descobriu
 * que a janela não existia.
 *
 * Sobe um contexto mínimo com {@code @EnableAsync} de verdade e segura o
 * orquestrador num latch: se a submissão voltar a ser síncrona, ela trava aqui.
 *
 * <p><b>Cada teste cria os próprios latches.</b> A primeira versão deste arquivo os
 * tinha como {@code static}, e o teste passava mesmo com o bug: o método que rodava
 * antes deixava o latch já liberado, e o seguinte nunca chegava a bloquear.
 */
@SpringJUnitConfig(AsyncScanSubmitTest.Contexto.class)
class AsyncScanSubmitTest {

    @EnableAsync
    @Configuration
    static class Contexto {

        @Bean
        BackgroundRunner background() {
            return new BackgroundRunner();
        }

        @Bean
        MessageCatalog catalog() {
            var source = new ResourceBundleMessageSource();
            source.setBasename("messages");
            source.setDefaultEncoding("UTF-8");
            source.setFallbackToSystemLocale(false);
            return new MessageCatalog(source);
        }

        /** Sem comportamento aqui: cada teste programa o seu, com os próprios latches. */
        @Bean
        ScanOrchestrator orchestrator() {
            return mock(ScanOrchestrator.class);
        }

        @Bean
        AsyncScanService asyncScanService(ScanOrchestrator orquestrador,
                                          MessageCatalog catalog,
                                          BackgroundRunner background) {
            return new AsyncScanService(orquestrador, mock(EmailService.class),
                    mock(AppUserRepository.class), mock(ScanEntitlementService.class),
                    catalog, background);
        }
    }

    @Autowired AsyncScanService service;
    @Autowired ScanOrchestrator orquestrador;

    /** Faz o orquestrador travar até {@code solta} ser liberado. */
    private CountDownLatch prendeOScan(CountDownLatch comecou, CountDownLatch solta) {
        when(orquestrador.execute(anyString(), anyBoolean(), any(), anyBoolean(),
                any(ScanOrigin.class), any(ScanProgress.class)))
                .thenAnswer(chamada -> {
                    comecou.countDown();
                    solta.await(10, TimeUnit.SECONDS);
                    return ScanResult.builder().build();
                });
        return solta;
    }

    @Test
    @DisplayName("submit volta enquanto o scan ainda roda, e o progresso já é consultável")
    void submitNaoEsperaOScanTerminar() throws Exception {
        CountDownLatch comecou = new CountDownLatch(1);
        CountDownLatch solta   = new CountDownLatch(1);
        prendeOScan(comecou, solta);
        String dono = "ip:198.51.100.7";

        try {
            // Síncrono, ficaria preso nos 10 segundos do latch.
            String scanId = assertTimeoutPreemptively(Duration.ofSeconds(3),
                    () -> service.submit("https://exemplo.test", true, null, true, false, dono),
                    "submit() bloqueou até o scan terminar — a chamada voltou a ser síncrona");

            assertTrue(comecou.await(3, TimeUnit.SECONDS), "o scan nem começou em outra thread");

            // A janela existe: com o scan preso, o cliente já consegue perguntar.
            AsyncScanStatus meio = service.getStatusFor(scanId, dono);
            assertNotNull(meio, "status indisponível durante o scan");
            assertFalse(meio.getProgress().isEmpty(),
                    "o feed chegou vazio justamente durante o scan");
            assertEquals(25, meio.getProgress().size(),
                    "scan ativo lista as verificações passivas e as ativas");
        } finally {
            solta.countDown();
        }
    }

    @Test
    @DisplayName("guest em scan passivo recebe as 25, com as ativas marcadas como não executadas")
    void guestVeOEscopoInteiro() throws Exception {
        // O feed é o mesmo para todo mundo: não há regra de plano nele. O que muda
        // entre planos é o acesso ao RESULTADO, e isso quem decide é outro serviço.
        CountDownLatch comecou = new CountDownLatch(1);
        CountDownLatch solta   = new CountDownLatch(1);
        prendeOScan(comecou, solta);
        String dono = "ip:198.51.100.8";

        try {
            String scanId = service.submit("https://exemplo.test", false, null, true, false, dono);
            assertTrue(comecou.await(3, TimeUnit.SECONDS));

            var progresso = service.getStatusFor(scanId, dono).getProgress();
            assertEquals(25, progresso.size());
            assertTrue(progresso.stream()
                    .filter(e -> e.phase().equals("ATIVA"))
                    .allMatch(e -> e.state().equals("NAO_EXECUTADA")));
        } finally {
            solta.countDown();
        }
    }

    @Test
    @DisplayName("progresso de outro dono não vaza junto com o status")
    void progressoRespeitaODono() throws Exception {
        // Mesma regra do resultado: quem não submeteu não recebe nem o andamento.
        CountDownLatch comecou = new CountDownLatch(1);
        CountDownLatch solta   = new CountDownLatch(1);
        prendeOScan(comecou, solta);

        try {
            String scanId = service.submit("https://exemplo.test", false, null, true, false,
                    "ip:203.0.113.1");
            assertTrue(comecou.await(3, TimeUnit.SECONDS));

            assertNotNull(service.getStatusFor(scanId, "ip:203.0.113.1"));
            assertNull(service.getStatusFor(scanId, "ip:203.0.113.9"));
        } finally {
            solta.countDown();
        }
    }
}
