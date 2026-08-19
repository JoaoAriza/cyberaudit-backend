package com.joao.cyberaudit.exception;

/**
 * Falha ao entregar um e-mail que É o próprio produto da operação.
 *
 * A maioria dos e-mails do sistema é acessória (aviso de scan concluído, alerta
 * de degradação): se não sair, o usuário não perde nada essencial, e engolir a
 * falha é a escolha certa — não vale derrubar a requisição por causa disso.
 *
 * O código 2FA é o oposto. Ele não acompanha a operação, ele É a operação: sem o
 * e-mail não existe segundo fator, e a tela de "digite o código" vira uma porta
 * sem chave. Como não há código de backup no sistema, engolir a falha ali não
 * degradava o serviço — trancava a conta para sempre.
 */
public class EmailDeliveryException extends RuntimeException {

    public EmailDeliveryException(String message, Throwable cause) {
        super(message, cause);
    }

    public EmailDeliveryException(String message) {
        super(message);
    }
}
