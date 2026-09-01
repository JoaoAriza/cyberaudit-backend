package com.joao.cyberaudit.service;

import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

/**
 * Roda uma tarefa fora da thread da requisição.
 *
 * <h2>Por que isto existe em vez de um {@code @Async} no próprio serviço</h2>
 *
 * {@code @Async} é implementado por proxy: o Spring embrulha o bean e é o embrulho
 * que troca de thread. Método anotado que é chamado de DENTRO da mesma classe não
 * passa pelo proxy — a chamada vai direto ao objeto, e a anotação não faz nada.
 * Nenhum aviso, nenhum erro: o código simplesmente roda síncrono.
 *
 * Foi o que aconteceu com o {@code /scan/async}. O {@code submit()} chamava o
 * próprio {@code executeAsync()}, então o POST executava o scan inteiro — os 25
 * checks — antes de devolver o {@code scanId}. O cliente recebia o id de um scan
 * que já tinha acabado, e o primeiro polling encontrava {@code DONE}. Como não
 * havia nada para mostrar no meio do caminho, ninguém percebeu.
 *
 * Chamar um bean SEPARADO é a saída sem sutileza: a chamada atravessa o proxy
 * porque atravessa a fronteira do objeto. Alternativas — injetar o próprio bean
 * com {@code @Lazy}, pedi-lo ao contexto — funcionam pelo mesmo mecanismo, mas
 * escondem a razão dentro de um truque que a próxima pessoa terá de decifrar.
 */
@Service
public class BackgroundRunner {

    @Async
    public void run(Runnable tarefa) {
        tarefa.run();
    }
}
