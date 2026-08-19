package com.joao.cyberaudit.service;

/**
 * Transporte de e-mail — só entrega, não sabe o que está entregando.
 *
 * Existe para separar POLÍTICA de TRANSPORTE. O {@link EmailService} monta o
 * conteúdo e decide o que fazer quando falha (engolir, no caso de aviso de scan;
 * propagar, no caso do código 2FA). A implementação daqui só reporta se saiu ou
 * não, sempre lançando {@link com.joao.cyberaudit.exception.EmailDeliveryException}
 * em caso de falha — quem decide o peso disso é quem chamou.
 *
 * Duas implementações, escolhidas por {@code mail.provider}:
 * SMTP (padrão, qualquer servidor) e Resend (HTTP, porta 443).
 */
public interface EmailSender {

    /**
     * @param from    remetente já resolvido (mail.from)
     * @param to      destinatário
     * @param subject assunto
     * @param html    corpo em HTML
     * @throws com.joao.cyberaudit.exception.EmailDeliveryException se não entregar
     */
    void send(String from, String to, String subject, String html);
}
