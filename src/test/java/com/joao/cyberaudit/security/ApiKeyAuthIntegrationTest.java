package com.joao.cyberaudit.security;

import com.joao.cyberaudit.dto.ApiKeyDto;
import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.AccountType;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.Plan;
import com.joao.cyberaudit.model.Role;
import com.joao.cyberaudit.repository.AccountRepository;
import com.joao.cyberaudit.repository.AppUserRepository;
import com.joao.cyberaudit.service.ApiKeyService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Autenticação por {@code X-Api-Key}, com a cadeia de filtros subida.
 *
 * Regressão do BUG-01 (cyberaudit-qa): toda request com API key — inclusive uma
 * chave válida recém-criada — respondia 401. O {@code ApiKeyService.validate}
 * devolvia o {@code createdBy} da chave, uma associação LAZY, depois que a
 * transação do repositório já tinha fechado; o filtro chamava
 * {@code getAuthorities()} no proxy sem sessão e estourava
 * {@code LazyInitializationException}. O filtro não autenticava e o entry point
 * respondia 401 — o mesmo 401 de uma chave revogada, então "revogada → 401"
 * passava pelo motivo errado.
 *
 * O teste NÃO é {@code @Transactional} de propósito: com uma transação aberta em
 * volta, o proxy inicializaria e o bug sumiria do teste sem sumir da produção.
 *
 * O alvo é {@code GET /api-keys}, que lê {@code user.getAccount()} — então além de
 * o filtro autenticar, o principal precisa chegar ao controller com a conta
 * carregada, como chega no fluxo JWT.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class ApiKeyAuthIntegrationTest {

    @Autowired private MockMvc mvc;
    @Autowired private ApiKeyService apiKeyService;
    @Autowired private AppUserRepository userRepository;
    @Autowired private AccountRepository accountRepository;

    /** Usuário PRO com conta: tem direito a API key e o controller responde 200. */
    private AppUser novoUsuarioPro() {
        Account account = accountRepository.save(Account.builder()
                .type(AccountType.INDIVIDUAL)
                .plan(Plan.PRO)
                .displayName("Conta API Key")
                .createdAt(LocalDateTime.now())
                .build());
        return userRepository.save(AppUser.builder()
                .name("Cliente API Key")
                .email("apikey-" + UUID.randomUUID() + "@example.com")
                .passwordHash("$2a$04$naoImportaParaEsteTeste000000000000000000000000000000")
                .role(Role.OWNER)
                .active(true)
                .createdAt(LocalDateTime.now())
                .account(account)
                .build());
    }

    private void listarComChave(String chave, int statusEsperado) throws Exception {
        mvc.perform(get("/api-keys").header(ApiKeyAuthFilter.HEADER, chave))
                .andExpect(status().is(statusEsperado));
    }

    // ── A regressão ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("chave válida autentica e o endpoint responde — 200")
    void chaveValidaAutentica() throws Exception {
        AppUser user = novoUsuarioPro();
        ApiKeyDto criada = apiKeyService.create("CI " + UUID.randomUUID(), user);

        listarComChave(criada.getPlainKey(), 200);
    }

    @Test
    @DisplayName("chave revogada deixa de autenticar — 401, depois de ter autenticado")
    void chaveRevogadaNaoAutentica() throws Exception {
        AppUser user = novoUsuarioPro();
        ApiKeyDto criada = apiKeyService.create("CI " + UUID.randomUUID(), user);

        // Controle: a mesma chave autentica antes da revogação. Sem isto o 401 de
        // baixo não distingue "revogada" de "API key quebrada", que era o bug.
        listarComChave(criada.getPlainKey(), 200);

        apiKeyService.revoke(criada.getId(), user);

        listarComChave(criada.getPlainKey(), 401);
    }

    @Test
    @DisplayName("chave com prefixo certo e segredo errado não autentica — 401")
    void chaveInexistenteNaoAutentica() throws Exception {
        AppUser user = novoUsuarioPro();
        ApiKeyDto criada = apiKeyService.create("CI " + UUID.randomUUID(), user);

        // Mesmo prefixo (11 chars) → cai no mesmo candidato; só o BCrypt recusa.
        String adulterada = criada.getPlainKey().substring(0, 11) + "0".repeat(24);
        listarComChave(adulterada, 401);
    }
}
