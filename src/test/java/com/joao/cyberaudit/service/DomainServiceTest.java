package com.joao.cyberaudit.service;

import com.joao.cyberaudit.dto.DomainDto;
import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.AccountType;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.Domain;
import com.joao.cyberaudit.model.Role;
import com.joao.cyberaudit.repository.DomainRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Contrato de add()/verify() que o OwnershipCard do frontend passou a chamar
 * (PlanLimitService.checkActiveScan unificado com o card de posse): a UI faz
 * POST /domains e, em 409, busca a lista para achar o id existente, depois
 * POST /domains/{id}/verify. Sem teste aqui, um formato de resposta diferente do
 * esperado quebraria esse fluxo silenciosamente — a UI só saberia ao clicar.
 */
class DomainServiceTest {

    private final DomainRepository repo = mock(DomainRepository.class);
    private final DomainProtectionService protection = mock(DomainProtectionService.class);
    private final DomainService service =
            new DomainService(repo, protection, mock(SubdomainEnumerationService.class));

    private AppUser usuario(Account account) {
        return AppUser.builder().id(UUID.randomUUID()).email("cliente@example.com")
                .role(Role.OWNER).account(account).build();
    }

    private Account conta() {
        return Account.builder().id(UUID.randomUUID()).type(AccountType.INDIVIDUAL).build();
    }

    @Test
    @DisplayName("add() cria o domínio não verificado e devolve id + token")
    void addCriaDominioNaoVerificado() {
        Account account = conta();
        AppUser user = usuario(account);
        when(repo.existsByAccountAndHost(eq(account), eq("meu-site.com"))).thenReturn(false);
        when(repo.save(any())).thenAnswer(inv -> {
            Domain d = inv.getArgument(0);
            d.setId(UUID.randomUUID());
            return d;
        });
        when(protection.generateVerificationToken("meu-site.com")).thenReturn("cyberaudit-verify=abc123");

        DomainDto dto = service.add("https://meu-site.com/", user);

        assertNotNull(dto.getId(), "frontend precisa do id para chamar /domains/{id}/verify");
        assertEquals("meu-site.com", dto.getHost(), "normalizado: sem protocolo nem trailing slash");
        assertFalse(dto.isVerified());
        assertEquals("cyberaudit-verify=abc123", dto.getVerificationToken());
    }

    @Test
    @DisplayName("add() do mesmo host duas vezes — 409, é isso que o card trata como \"já existe\"")
    void addDuplicadoDaConflito() {
        Account account = conta();
        when(repo.existsByAccountAndHost(eq(account), eq("meu-site.com"))).thenReturn(true);

        var erro = assertThrows(ResponseStatusException.class,
                () -> service.add("meu-site.com", usuario(account)));
        assertEquals(HttpStatus.CONFLICT, erro.getStatusCode());
    }

    @Test
    @DisplayName("verify() marca verified=true quando o arquivo .well-known confere")
    void verifyConfirmaQuandoArquivoConfere() {
        Account account = conta();
        UUID id = UUID.randomUUID();
        Domain domain = Domain.builder().id(id).account(account).host("meu-site.com")
                .verified(false).createdAt(LocalDateTime.now()).build();
        when(repo.findById(id)).thenReturn(Optional.of(domain));
        when(repo.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(protection.isOwnershipVerified("meu-site.com")).thenReturn(true);
        when(protection.generateVerificationToken("meu-site.com")).thenReturn("cyberaudit-verify=abc123");

        DomainDto dto = service.verify(id, usuario(account));

        assertTrue(dto.isVerified());
        assertNotNull(dto.getVerifiedAt());
    }

    @Test
    @DisplayName("verify() recusa (417) quando o arquivo não confere — card mostra \"não encontrado\"")
    void verifyRecusaQuandoArquivoNaoConfere() {
        Account account = conta();
        UUID id = UUID.randomUUID();
        Domain domain = Domain.builder().id(id).account(account).host("meu-site.com")
                .verified(false).createdAt(LocalDateTime.now()).build();
        when(repo.findById(id)).thenReturn(Optional.of(domain));
        when(protection.isOwnershipVerified("meu-site.com")).thenReturn(false);

        var erro = assertThrows(ResponseStatusException.class,
                () -> service.verify(id, usuario(account)));
        assertEquals(HttpStatus.EXPECTATION_FAILED, erro.getStatusCode());
    }

    @Test
    @DisplayName("verify() de domínio de outra conta — 403, isolamento entre contas")
    void verifyDeOutraContaNegaAcesso() {
        Account minhaConta = conta();
        Account outraConta = conta();
        UUID id = UUID.randomUUID();
        Domain domainDeOutraConta = Domain.builder().id(id).account(outraConta).host("nao-e-meu.com")
                .verified(false).createdAt(LocalDateTime.now()).build();
        when(repo.findById(id)).thenReturn(Optional.of(domainDeOutraConta));

        var erro = assertThrows(ResponseStatusException.class,
                () -> service.verify(id, usuario(minhaConta)));
        assertEquals(HttpStatus.FORBIDDEN, erro.getStatusCode());
    }
}
