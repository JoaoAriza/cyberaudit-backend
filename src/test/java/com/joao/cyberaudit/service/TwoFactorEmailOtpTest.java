package com.joao.cyberaudit.service;

import com.joao.cyberaudit.exception.EmailDeliveryException;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.OtpCode;
import com.joao.cyberaudit.repository.AppUserRepository;
import com.joao.cyberaudit.repository.OtpCodeRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Ativação do 2FA por e-mail.
 *
 * O caso que motivou estes testes: ativar Email OTP com o SMTP quebrado deixava
 * a conta inacessível para sempre — o login passava a exigir um código que nunca
 * chegava, desativar exigia estar logado, e não existe código de backup. O envio
 * tem de ser provado ANTES de a flag ser gravada.
 */
class TwoFactorEmailOtpTest {

    private final OtpCodeRepository otpRepo   = mock(OtpCodeRepository.class);
    private final AppUserRepository userRepo  = mock(AppUserRepository.class);
    private final EmailService      email     = mock(EmailService.class);

    private TwoFactorService service() {
        return new TwoFactorService(mock(TotpService.class), email, otpRepo, userRepo);
    }

    private AppUser usuario() {
        return AppUser.builder()
                .id(UUID.randomUUID())
                .email("cliente@example.com")
                .name("Cliente Teste")
                .build();
    }

    @Test
    @DisplayName("e-mail falhando: a ativação falha e a flag NÃO é gravada")
    void naoAtivaQuandoEnvioFalha() {
        doThrow(new EmailDeliveryException("SMTP recusou"))
                .when(email).sendOtpEmail(anyString(), anyString(), anyString(), anyBoolean());

        AppUser user = usuario();

        assertThrows(EmailDeliveryException.class, () -> service().enableEmailOtp(user));

        assertFalse(user.isEmailOtpEnabled(),
                "ativar com e-mail quebrado tranca a conta — a flag não pode ser gravada");
        verify(userRepo, never()).save(any(AppUser.class));
    }

    @Test
    @DisplayName("e-mail funcionando: ativa normalmente")
    void ativaQuandoEnvioFunciona() {
        AppUser user = usuario();
        when(otpRepo.save(any(OtpCode.class))).thenAnswer(i -> i.getArgument(0));

        assertDoesNotThrow(() -> service().enableEmailOtp(user));

        assertTrue(user.isEmailOtpEnabled());
        verify(userRepo).save(user);
    }

    @Test
    @DisplayName("o código é gravado antes do envio — é o que permite destravar pelo banco")
    void codigoEGravadoAntesDoEnvio() {
        doThrow(new EmailDeliveryException("SMTP recusou"))
                .when(email).sendOtpEmail(anyString(), anyString(), anyString(), anyBoolean());

        assertThrows(EmailDeliveryException.class, () -> service().sendEmailOtp(usuario()));

        verify(otpRepo).save(any(OtpCode.class));
    }

    /*
     * ATENÇÃO ao teste acima: ele prova a ORDEM das chamadas, não que a linha
     * sobreviva no banco. Com mocks não há transação, então o rollback não
     * aparece aqui — e foi exatamente esse o furo: `sendEmailOtp` é
     * @Transactional, a exceção derrubava a transação e o OtpCode ia junto,
     * apesar de este teste passar.
     *
     * O que garante a persistência é o `noRollbackFor = EmailDeliveryException`
     * na anotação. Isso é comportamento do proxy do Spring e só um teste com
     * contexto e banco de verdade cobriria (hoje não há infraestrutura para
     * isso no projeto — ver a pendência de spring-security-test + H2).
     */
}
