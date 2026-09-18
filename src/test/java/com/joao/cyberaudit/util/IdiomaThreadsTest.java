package com.joao.cyberaudit.util;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.i18n.LocaleContextHolder;

import java.util.Locale;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * O idioma da requisição atravessa para as threads dos pools do scan.
 *
 * O buraco que este teste fecha: {@code LocaleContextHolder} é ThreadLocal, quase
 * todo módulo do scan roda dentro de um pool, e é lá que o texto do achado é
 * montado. A thread do pool nascia sem contexto e {@code getLocale()} devolvia o
 * locale da JVM — o do SERVIDOR. Um cliente em inglês recebia as Issues em inglês
 * (montadas na thread do scan) e os módulos no idioma da hospedagem, sem erro
 * nenhum no log. {@link #poolPadraoPerdeOIdioma()} registra o comportamento que
 * torna isso possível, para ninguém "simplificar" a fábrica de volta.
 */
class IdiomaThreadsTest {

    @AfterEach
    void limpaIdioma() {
        LocaleContextHolder.resetLocaleContext();
    }

    private Locale idiomaDentroDoPool(ExecutorService pool) throws Exception {
        try {
            return CompletableFuture.supplyAsync(LocaleContextHolder::getLocale, pool).get();
        } catch (InterruptedException | ExecutionException e) {
            throw new AssertionError(e);
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    @DisplayName("a tarefa no pool vê o idioma de quem montou o pool")
    void tarefaHerdaOIdioma() throws Exception {
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        ExecutorService pool = Executors.newFixedThreadPool(2, IdiomaThreads.fabrica("teste"));

        assertEquals(Locale.ENGLISH, idiomaDentroDoPool(pool));
    }

    @Test
    @DisplayName("idioma capturado é o do momento em que o pool nasce, não o da tarefa")
    void idiomaEhFixadoNaCriacao() throws Exception {
        LocaleContextHolder.setLocale(Locale.forLanguageTag("pt-BR"));
        ExecutorService pool = Executors.newFixedThreadPool(1, IdiomaThreads.fabrica("teste"));

        // Troca depois de criar a fábrica: o scan que já começou não muda de idioma
        // no meio — o laudo carimba o idioma em que nasceu.
        LocaleContextHolder.setLocale(Locale.ENGLISH);

        assertEquals(Locale.forLanguageTag("pt-BR"), idiomaDentroDoPool(pool));
    }

    @Test
    @DisplayName("todas as threads do pool recebem o idioma, não só a primeira")
    void todasAsThreads() throws Exception {
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        ExecutorService pool = Executors.newFixedThreadPool(4, IdiomaThreads.fabrica("teste"));
        try {
            var tarefas = java.util.stream.IntStream.range(0, 4)
                    .mapToObj(i -> CompletableFuture.supplyAsync(() -> {
                        // Segura a thread para forçar o pool a criar as quatro.
                        try { Thread.sleep(40); } catch (InterruptedException ignored) {}
                        return LocaleContextHolder.getLocale();
                    }, pool))
                    .toList();

            for (var t : tarefas) assertEquals(Locale.ENGLISH, t.get());
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    @DisplayName("pool com a fábrica padrão NÃO herda — é o bug que a fábrica existe para tapar")
    void poolPadraoPerdeOIdioma() throws Exception {
        // Idioma que a JVM não tem como ser por padrão em nenhuma máquina de CI.
        Locale exotico = Locale.forLanguageTag("qps-ploc");
        LocaleContextHolder.setLocale(exotico);

        assertNotEquals(exotico, idiomaDentroDoPool(Executors.newFixedThreadPool(1)),
                "se isto passar a herdar, a fábrica ficou redundante — confirme antes de removê-la");
    }
}
