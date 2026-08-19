package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.PasswordResetToken;
import com.joao.cyberaudit.repository.AppUserRepository;
import com.joao.cyberaudit.repository.PasswordResetTokenRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Redefinição de senha.
 *
 * O foco aqui são as propriedades de segurança, não o caminho feliz: o que o
 * banco guarda, o que a resposta revela e o que acontece com token usado,
 * expirado ou forjado.
 */
class PasswordResetServiceTest {

    private static final String EMAIL = "cliente@example.com";

    private final PasswordResetTokenRepository tokenRepo = mock(PasswordResetTokenRepository.class);
    private final AppUserRepository            userRepo  = mock(AppUserRepository.class);
    private final EmailService                 email     = mock(EmailService.class);
    private final AuditService                 audit     = mock(AuditService.class);
    private final PasswordEncoder              encoder   = new BCryptPasswordEncoder(4); // rápido no teste

    private PasswordResetService service() {
        var s = new PasswordResetService(tokenRepo, userRepo, email, encoder, audit);
        ReflectionTestUtils.setField(s, "appBaseUrl", "https://cyberauditapp.com");
        return s;
    }

    private AppUser usuario() {
        return AppUser.builder()
                .id(UUID.randomUUID())
                .email(EMAIL)
                .name("Cliente Teste")
                .passwordHash(encoder.encode("SenhaAntiga#1"))
                .active(true)
                .build();
    }

    // ── Pedido ───────────────────────────────────────────────────────────────

    @Test
    @DisplayName("e-mail inexistente não lança nem envia — não vira verificador de cadastro")
    void emailInexistenteNaoRevelaNada() {
        when(userRepo.findByEmail(anyString())).thenReturn(Optional.empty());

        assertDoesNotThrow(() -> service().requestReset("naoexiste@example.com"));

        verify(email, never()).sendPasswordResetEmail(anyString(), anyString(), anyString(), anyInt());
        verify(tokenRepo, never()).save(any(PasswordResetToken.class));
    }

    @Test
    @DisplayName("conta desativada também não recebe link")
    void contaDesativadaNaoRecebe() {
        AppUser user = usuario();
        user.setActive(false);
        when(userRepo.findByEmail(EMAIL)).thenReturn(Optional.of(user));

        service().requestReset(EMAIL);

        verify(email, never()).sendPasswordResetEmail(anyString(), anyString(), anyString(), anyInt());
    }

    @Test
    @DisplayName("o banco guarda o HASH do token, nunca o valor que vai no link")
    void bancoGuardaHashNaoOToken() {
        when(userRepo.findByEmail(EMAIL)).thenReturn(Optional.of(usuario()));

        service().requestReset(EMAIL);

        var tokenSalvo = ArgumentCaptor.forClass(PasswordResetToken.class);
        verify(tokenRepo).save(tokenSalvo.capture());

        var linkEnviado = ArgumentCaptor.forClass(String.class);
        verify(email).sendPasswordResetEmail(anyString(), anyString(), linkEnviado.capture(), anyInt());

        String tokenDoLink = linkEnviado.getValue().replaceAll(".*token=", "");
        String hashSalvo   = tokenSalvo.getValue().getTokenHash();

        assertNotEquals(tokenDoLink, hashSalvo,
                "guardar o token em claro entregaria as contas num vazamento de banco");
        assertEquals(64, hashSalvo.length(), "SHA-256 em hexadecimal tem 64 caracteres");
        assertFalse(linkEnviado.getValue().contains(hashSalvo));
    }

    @Test
    @DisplayName("pedido novo apaga os anteriores — só o último link vale")
    void pedidoNovoInvalidaAnteriores() {
        AppUser user = usuario();
        when(userRepo.findByEmail(EMAIL)).thenReturn(Optional.of(user));

        service().requestReset(EMAIL);

        verify(tokenRepo).deleteByUserId(user.getId());
    }

    @Test
    @DisplayName("o token é gravado ANTES do e-mail sair — link enviado nunca aponta para nada")
    void tokenGravadoAntesDoEnvio() {
        when(userRepo.findByEmail(EMAIL)).thenReturn(Optional.of(usuario()));

        service().requestReset(EMAIL);

        // A ordem é o que impede o cenário que ocorreu em produção: e-mail entregue
        // e token descartado depois, deixando um link morto na caixa do usuário.
        var ordem = org.mockito.Mockito.inOrder(tokenRepo, email);
        ordem.verify(tokenRepo).save(any(PasswordResetToken.class));
        ordem.verify(email).sendPasswordResetEmail(anyString(), anyString(), anyString(), anyInt());
    }

    @Test
    @DisplayName("falha de envio não propaga — propagar diria que a conta existe")
    void falhaDeEnvioNaoVaza() {
        when(userRepo.findByEmail(EMAIL)).thenReturn(Optional.of(usuario()));
        org.mockito.Mockito.doThrow(new com.joao.cyberaudit.exception.EmailDeliveryException("SMTP fora"))
                .when(email).sendPasswordResetEmail(anyString(), anyString(), anyString(), anyInt());

        assertDoesNotThrow(() -> service().requestReset(EMAIL));
    }

    // ── Consumo ──────────────────────────────────────────────────────────────

    private PasswordResetToken tokenValido(UUID userId, String hash) {
        return PasswordResetToken.builder()
                .id(UUID.randomUUID())
                .userId(userId)
                .tokenHash(hash)
                .expiresAt(LocalDateTime.now().plusMinutes(30))
                .used(false)
                .createdAt(LocalDateTime.now())
                .build();
    }

    @Test
    @DisplayName("token válido troca a senha e marca o token como usado")
    void trocaSenhaComTokenValido() {
        AppUser user = usuario();
        String hashAntigo = user.getPasswordHash();
        var prt = tokenValido(user.getId(), "qualquer");

        when(tokenRepo.findByTokenHashAndUsedFalse(anyString())).thenReturn(Optional.of(prt));
        when(userRepo.findById(user.getId())).thenReturn(Optional.of(user));

        service().resetPassword("token-cru", "SenhaNova#2026");

        assertNotEquals(hashAntigo, user.getPasswordHash());
        assertTrue(encoder.matches("SenhaNova#2026", user.getPasswordHash()));
        assertTrue(prt.isUsed(), "token de uso único precisa ficar marcado");
    }

    @Test
    @DisplayName("token expirado é recusado mesmo estando no banco e não usado")
    void tokenExpiradoRecusado() {
        AppUser user = usuario();
        var prt = tokenValido(user.getId(), "qualquer");
        prt.setExpiresAt(LocalDateTime.now().minusMinutes(1));

        when(tokenRepo.findByTokenHashAndUsedFalse(anyString())).thenReturn(Optional.of(prt));

        var erro = assertThrows(ResponseStatusException.class,
                () -> service().resetPassword("token-cru", "SenhaNova#2026"));
        assertEquals(422, erro.getStatusCode().value());
    }

    @Test
    @DisplayName("token inexistente/forjado é recusado")
    void tokenForjadoRecusado() {
        when(tokenRepo.findByTokenHashAndUsedFalse(anyString())).thenReturn(Optional.empty());

        assertThrows(ResponseStatusException.class,
                () -> service().resetPassword("forjado", "SenhaNova#2026"));
    }

    @Test
    @DisplayName("senha curta é recusada antes de qualquer consulta ao token")
    void senhaCurtaRecusada() {
        var erro = assertThrows(ResponseStatusException.class,
                () -> service().resetPassword("token-cru", "123"));

        assertEquals(400, erro.getStatusCode().value());
        verify(tokenRepo, never()).findByTokenHashAndUsedFalse(anyString());
    }

    @Test
    @DisplayName("token em branco é recusado")
    void tokenEmBrancoRecusado() {
        assertThrows(ResponseStatusException.class,
                () -> service().resetPassword("  ", "SenhaNova#2026"));
    }
}
