package com.joao.cyberaudit.service;

import com.joao.cyberaudit.exception.EmailDeliveryException;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Component;

/**
 * Transporte por SMTP — o comportamento que o sistema sempre teve.
 *
 * Continua sendo o padrão para quem roda com servidor próprio (nginx/Postfix) ou
 * qualquer provedor SMTP. Em PaaS costuma ser o caminho problemático: as portas
 * 465/587 são alvo comum de bloqueio de saída, e provedores de e-mail gratuito
 * recusam conexão vinda de IP de datacenter compartilhado.
 */
@Component
@ConditionalOnProperty(name = "mail.provider", havingValue = "smtp", matchIfMissing = true)
public class SmtpEmailSender implements EmailSender {

    private final JavaMailSender mailSender;

    public SmtpEmailSender(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    @Override
    public void send(String from, String to, String subject, String html) {
        try {
            MimeMessage msg = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(msg, false, "UTF-8");
            helper.setFrom(from);
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(html, true);
            mailSender.send(msg);
        } catch (MessagingException | RuntimeException e) {
            throw new EmailDeliveryException("SMTP: " + e.getMessage(), e);
        }
    }
}
