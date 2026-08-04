package com.joao.cyberaudit.service;

import com.joao.cyberaudit.exception.ScanCapacityException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * Teto global de scans simultâneos.
 *
 * Cada scan abre ~16 threads (fase passiva 8 + ativa 6 + fingerprint 2) e dispara
 * dezenas de requisições de saída. Sem teto, N requisições concorrentes viram N×16
 * threads: derrubar a instância custa um laço de curl. O semáforo transforma
 * excesso de carga em fila com timeout e, no limite, em 503 — não em OOM.
 */
@Service
public class ScanConcurrencyLimiter {

    private final Semaphore slots;
    private final int       maxConcurrent;
    private final int       acquireTimeoutSeconds;

    public ScanConcurrencyLimiter(
            @Value("${scan.max-concurrent:4}") int maxConcurrent,
            @Value("${scan.acquire-timeout-seconds:20}") int acquireTimeoutSeconds) {
        this.maxConcurrent         = Math.max(1, maxConcurrent);
        this.acquireTimeoutSeconds = Math.max(1, acquireTimeoutSeconds);
        // fair=true: FIFO, evita que uma requisição fique presa enquanto outras passam
        this.slots = new Semaphore(this.maxConcurrent, true);
    }

    /**
     * Executa {@code work} ocupando um slot. Espera até o timeout por um slot livre;
     * estourando, lança {@link ScanCapacityException} (503).
     */
    public <T> T withSlot(Supplier<T> work) {
        boolean acquired = false;
        try {
            acquired = slots.tryAcquire(acquireTimeoutSeconds, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ScanCapacityException(
                    "Scan interrompido enquanto aguardava capacidade. Tente novamente.");
        }

        if (!acquired) {
            throw new ScanCapacityException(
                    "Capacidade de scan esgotada (" + maxConcurrent + " simultâneos). "
                            + "Tente novamente em alguns instantes.");
        }

        try {
            return work.get();
        } finally {
            slots.release();
        }
    }

    /** Scans em execução no momento — exposto para o endpoint de status/monitoramento. */
    public int inFlight() {
        return maxConcurrent - slots.availablePermits();
    }

    public int capacity() {
        return maxConcurrent;
    }
}
