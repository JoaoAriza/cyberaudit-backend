package com.joao.cyberaudit.controller;

import com.joao.cyberaudit.service.BillingService;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Gatilho de teste — existe SÓ sob o profile {@code qa-docker} (ambiente do
 * cyberaudit-qa), nunca em produção. Dispara manualmente o job de expiração de Pix
 * que normalmente roda apenas via {@code @Scheduled} (cron diário 3h), para o caso
 * PAY-10 poder testar o rebaixamento por API (caixa-preta) em vez de esperar o cron.
 *
 * Fica sob {@code /admin/**} (exige OWNER/ADMIN pela SecurityConfig), então não é um
 * endpoint anônimo — e o {@code @Profile} garante que ele não exista fora do teste.
 */
@RestController
@Profile("qa-docker")
public class TestBillingController {

    private final BillingService billingService;

    public TestBillingController(BillingService billingService) {
        this.billingService = billingService;
    }

    @PostMapping("/admin/test/expire-pix")
    public ResponseEntity<String> expirePix() {
        billingService.expirarAssinaturasPixVencidas();
        return ResponseEntity.ok("expired");
    }
}
