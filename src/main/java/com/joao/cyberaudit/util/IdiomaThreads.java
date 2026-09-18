package com.joao.cyberaudit.util;

import org.springframework.context.i18n.LocaleContextHolder;

import java.util.Locale;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Threads de pool que carregam o idioma de quem pediu o scan.
 *
 * O {@link LocaleContextHolder} é ThreadLocal. Thread de pool nasce sem contexto
 * nenhum, e ali {@code getLocale()} devolve o locale da JVM — o do SERVIDOR. É
 * exatamente a decisão que o {@code LocaleConfig} e o
 * {@code spring.messages.fallback-to-system-locale=false} existem para tirar da
 * máquina: o laudo sai no idioma do cliente, não no da hospedagem.
 *
 * <p>O detalhe que fazia o buraco passar despercebido: quase todo módulo do scan
 * roda dentro de um pool (ver {@code ScanOrchestrator}), e é lá que o texto do
 * achado é montado pelo {@code MessageCatalog}. O idioma que o
 * {@code AsyncScanService} reinstala na thread do scan não atravessava para os
 * pools — então um cliente em inglês recebia os módulos no idioma do servidor,
 * enquanto as Issues (montadas na thread do scan, pelo {@code ScoreService})
 * saíam corretas. Meio laudo em cada idioma, sem erro nenhum no log.
 *
 * <p>O idioma é capturado quando a FÁBRICA é criada — na thread que está montando
 * o pool, que é a que tem o contexto. Fica gravado em cada thread nova e vale
 * para todas as tarefas que ela atender. Não há limpeza no fim porque o pool
 * nasce e morre dentro de um scan: {@code shutdownNow()} descarta as threads.
 * Pool reaproveitado entre requisições precisaria embrulhar tarefa por tarefa.
 */
public final class IdiomaThreads {

    private IdiomaThreads() {}

    /** Fábrica que fixa, em cada thread criada, o idioma vigente AGORA. */
    public static ThreadFactory fabrica(String nome) {
        final Locale idioma = LocaleContextHolder.getLocale();
        final AtomicInteger seq = new AtomicInteger(1);
        // Fora do idioma e do nome, a thread é igual à do
        // Executors.defaultThreadFactory(): mesma prioridade, também não-daemon. O
        // que esta fábrica faz é carregar o idioma — e só.
        return tarefa -> new Thread(() -> {
            LocaleContextHolder.setLocale(idioma);
            tarefa.run();
        }, nome + "-" + seq.getAndIncrement());
    }
}
