package com.joao.cyberaudit.service;

import com.joao.cyberaudit.exception.ScanCapacityException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScanConcurrencyLimiterTest {

    /** Catálogo real: a mensagem de capacidade esgotada chega ao cliente por ele. */
    private MessageCatalog catalogo() {
        var source = new org.springframework.context.support.ResourceBundleMessageSource();
        source.setBasename("messages");
        source.setDefaultEncoding("UTF-8");
        source.setFallbackToSystemLocale(false);
        return new MessageCatalog(source);
    }

    @Test
    @DisplayName("libera o slot mesmo quando o trabalho lança")
    void liberaSlotEmExcecao() {
        ScanConcurrencyLimiter limiter = new ScanConcurrencyLimiter(catalogo(), 1, 1);

        assertThrows(IllegalStateException.class, () -> limiter.withSlot(() -> {
            throw new IllegalStateException("falha do scan");
        }));

        assertEquals(0, limiter.inFlight(), "slot deve voltar para o pool");
        assertEquals("ok", limiter.withSlot(() -> "ok"));
    }

    @Test
    @DisplayName("recusa com 503 quando a capacidade está esgotada")
    void recusaQuandoLotado() throws Exception {
        ScanConcurrencyLimiter limiter = new ScanConcurrencyLimiter(catalogo(), 1, 1);
        CountDownLatch ocupado  = new CountDownLatch(1);
        CountDownLatch liberar  = new CountDownLatch(1);
        ExecutorService pool    = Executors.newSingleThreadExecutor();

        try {
            pool.submit(() -> limiter.withSlot(() -> {
                ocupado.countDown();
                try { liberar.await(5, TimeUnit.SECONDS); } catch (InterruptedException ignored) {}
                return "primeiro";
            }));

            assertTrue(ocupado.await(5, TimeUnit.SECONDS), "o primeiro scan deve tomar o slot");
            assertEquals(1, limiter.inFlight());

            // timeout de 1s configurado acima — este não consegue slot
            assertThrows(ScanCapacityException.class, () -> limiter.withSlot(() -> "segundo"));
        } finally {
            liberar.countDown();
            pool.shutdown();
            pool.awaitTermination(5, TimeUnit.SECONDS);
        }

        assertEquals(0, limiter.inFlight());
    }

    @Test
    @DisplayName("nunca deixa passar mais que a capacidade configurada")
    void respeitaCapacidade() throws Exception {
        int capacidade = 3;
        ScanConcurrencyLimiter limiter = new ScanConcurrencyLimiter(catalogo(), capacidade, 10);
        AtomicInteger simultaneos = new AtomicInteger();
        AtomicInteger pico        = new AtomicInteger();
        ExecutorService pool      = Executors.newFixedThreadPool(16);
        CountDownLatch terminou   = new CountDownLatch(16);

        for (int i = 0; i < 16; i++) {
            pool.submit(() -> {
                try {
                    limiter.withSlot(() -> {
                        pico.accumulateAndGet(simultaneos.incrementAndGet(), Math::max);
                        try { Thread.sleep(20); } catch (InterruptedException ignored) {}
                        simultaneos.decrementAndGet();
                        return null;
                    });
                } finally {
                    terminou.countDown();
                }
            });
        }

        assertTrue(terminou.await(30, TimeUnit.SECONDS), "todos os scans devem completar");
        pool.shutdown();

        assertTrue(pico.get() <= capacidade,
                "pico de simultâneos foi " + pico.get() + ", capacidade é " + capacidade);
        assertEquals(0, limiter.inFlight());
    }

    @Test
    @DisplayName("capacidade mínima de 1 mesmo com configuração inválida")
    void normalizaConfiguracaoInvalida() {
        ScanConcurrencyLimiter limiter = new ScanConcurrencyLimiter(catalogo(), 0, 0);
        assertEquals(1, limiter.capacity());
        assertEquals("ok", limiter.withSlot(() -> "ok"));
    }
}
