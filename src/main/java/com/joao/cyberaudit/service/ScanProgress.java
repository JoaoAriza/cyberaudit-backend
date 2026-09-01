package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.ScanCheck;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * O que o scan já apurou, enquanto ele ainda está rodando.
 *
 * A tela mostrava só um spinner e, depois de 30 segundos, um aviso de que estava
 * demorando — sem dizer demorando em quê. O scan roda 25 verificações nomeadas em
 * três levas paralelas; o cliente não via nenhuma delas.
 *
 * <h2>Por que o estado mora aqui e não no {@code ScanResult}</h2>
 *
 * O resultado só existe quando tudo acabou. Este objeto é o oposto: nasce vazio,
 * é escrito pelas threads dos pools enquanto trabalham, e é lido pelo polling do
 * cliente no meio do caminho. Por isso é {@link ConcurrentHashMap} — as
 * verificações rodam em paralelo e escrevem ao mesmo tempo.
 *
 * <h2>O idioma resolve na leitura, não na escrita</h2>
 *
 * {@link #instantaneo()} traduz os rótulos no momento em que o polling pergunta,
 * usando o locale daquela requisição. É de propósito: quem troca o idioma no meio
 * de um scan vê o feed acompanhar. Diferente do {@code ScanResult}, que carimba o
 * idioma em que nasceu — mas ali o texto precisa ser estável porque é laudo, e
 * aqui ele desaparece quando o scan termina.
 */
public class ScanProgress {

    /**
     * Estado de uma verificação.
     *
     * {@code PULADO} não é falha: é decisão do scan — probe de injeção sem
     * parâmetro para injetar, port scan sem host. Aparece separado de
     * {@code FALHOU} para o feed não acusar problema onde não houve.
     */
    public enum Estado { PENDENTE, RODANDO, OK, FALHOU, PULADO }

    /** Uma linha do feed, pronta para o cliente. */
    public record Etapa(String check, String module, String label, String phase, String state) {}

    private final MessageCatalog catalog;
    private final boolean incluiAtivas;
    private final Map<ScanCheck, Estado> estados = new ConcurrentHashMap<>();

    public ScanProgress(MessageCatalog catalog, boolean incluiAtivas) {
        this.catalog      = catalog;
        this.incluiAtivas = incluiAtivas;
    }

    /**
     * Progresso que não é observado por ninguém — os caminhos síncronos de scan.
     *
     * {@code /scan}, o scan por API key e o agendado devolvem o resultado pronto:
     * não há polling para alimentar. Objeto nulo em vez de {@code null} para o
     * orquestrador não ter de checar em 25 lugares.
     */
    public static ScanProgress desligado() {
        return new ScanProgress(null, false);
    }

    /**
     * Embrulha a tarefa de uma verificação para ela mesma anunciar quando começa e
     * quando termina.
     *
     * A exceção é remarcada depois de registrar a falha: o {@code .exceptionally()}
     * que vem depois no orquestrador continua sendo quem decide o valor de retorno.
     * Este objeto observa, não interfere.
     */
    public <T> Supplier<T> acompanha(ScanCheck check, Supplier<T> tarefa) {
        if (catalog == null) return tarefa;
        return () -> {
            estados.put(check, Estado.RODANDO);
            try {
                T valor = tarefa.get();
                estados.put(check, Estado.OK);
                return valor;
            } catch (RuntimeException | Error e) {
                estados.put(check, Estado.FALHOU);
                throw e;
            }
        };
    }

    /** Marca uma verificação diretamente — para as que não passam por um pool. */
    public void registra(ScanCheck check, Estado estado) {
        if (catalog == null) return;
        estados.put(check, estado);
    }

    /**
     * Alinha o progresso ao {@code moduleStatus} no fim de cada fase.
     *
     * Sem isto, verificação que estourou o teto de 120 segundos ficaria
     * eternamente {@code RODANDO} no feed: quem marca {@code OK} é a própria
     * tarefa, e a tarefa que não terminou nunca marca nada. O
     * {@code moduleStatus} é a fonte da verdade do que aconteceu de fato — o feed
     * é a projeção dele.
     */
    public void sincroniza(Map<String, String> moduleStatus) {
        if (catalog == null) return;
        moduleStatus.forEach((nome, estado) -> {
            ScanCheck check = porNome(nome);
            if (check == null) return;
            estados.put(check, switch (estado) {
                case "OK"      -> Estado.OK;
                case "SKIPPED" -> Estado.PULADO;
                default        -> Estado.FALHOU;   // TIMEOUT, ERROR
            });
        });
    }

    /**
     * A lista inteira, na ordem do enum, com o estado de cada verificação agora.
     *
     * Devolve todas — inclusive as pendentes — porque o feed mostra o caminho
     * completo desde o primeiro instante. Saber que faltam dezoito é informação;
     * ver linhas aparecerem do nada, não.
     */
    public List<Etapa> instantaneo() {
        if (catalog == null) return List.of();
        return Arrays.stream(ScanCheck.values())
                .filter(c -> incluiAtivas || !c.ativa())
                .map(c -> new Etapa(
                        c.name(),
                        c.moduloUi(),
                        catalog.check(c.name()),
                        c.fase().name(),
                        estados.getOrDefault(c, Estado.PENDENTE).name()))
                .toList();
    }

    private static ScanCheck porNome(String nome) {
        try { return ScanCheck.valueOf(nome); }
        catch (IllegalArgumentException e) { return null; }
    }
}
