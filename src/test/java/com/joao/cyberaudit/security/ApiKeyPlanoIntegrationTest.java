package com.joao.cyberaudit.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.AccountType;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.Plan;
import com.joao.cyberaudit.model.Role;
import com.joao.cyberaudit.repository.AccountRepository;
import com.joao.cyberaudit.repository.AppUserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Quem pode criar API key — pela rota real, com a cadeia de filtros subida.
 *
 * Regressão do BUG-18 (cyberaudit-qa): a checagem saía cedo para {@code Role.OWNER}
 * e {@code ADMIN}, e todo cadastro nasce OWNER da própria conta. O ramo do FREE nunca
 * era alcançado: qualquer conta grátis criava chave. A conta Empresa também saía cedo
 * em qualquer plano, e o cadastro deixa escolher "Empresa" no FREE.
 *
 * Regra decidida pelo dono (2026-11-17): criar chave é de plano pago — PRO, ENTERPRISE
 * e equipe da plataforma. Chave que já existe continua valendo mesmo se a conta voltar
 * para o FREE, e continua listável e revogável.
 *
 * Todo usuário aqui é OWNER, como sai do cadastro: com outro papel o teste passaria
 * contra o código antigo pelo motivo errado.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestPropertySource(properties = "platform.staff-emails=" + ApiKeyPlanoIntegrationTest.STAFF)
class ApiKeyPlanoIntegrationTest {

    static final String STAFF = "staff-apikey@cyberaudit.test";

    @Autowired private MockMvc mvc;
    @Autowired private JwtUtil jwtUtil;
    @Autowired private AppUserRepository userRepository;
    @Autowired private AccountRepository accountRepository;
    @Autowired private ObjectMapper json;

    private AppUser novoDono(AccountType tipo, Plan plano) {
        return novoUsuario(tipo, plano, Role.OWNER, "apikey-plano-" + UUID.randomUUID() + "@example.com");
    }

    private AppUser novoUsuario(AccountType tipo, Plan plano, Role papel, String email) {
        Account account = accountRepository.save(Account.builder()
                .type(tipo)
                .plan(plano)
                .displayName("Conta " + tipo + " " + plano)
                .createdAt(LocalDateTime.now())
                .build());
        return userRepository.save(AppUser.builder()
                .name("Cliente " + plano)
                .email(email)
                .passwordHash("$2a$04$naoImportaParaEsteTeste000000000000000000000000000000")
                .role(papel)
                .active(true)
                .createdAt(LocalDateTime.now())
                .account(account)
                .build());
    }

    private ResultActions criarChave(AppUser user) throws Exception {
        return mvc.perform(post("/api-keys")
                .header("Authorization", "Bearer " + jwtUtil.generateToken(user))
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"CI " + UUID.randomUUID() + "\"}"));
    }

    // ── A regressão: FREE não cria ──────────────────────────────────────────

    @Test
    @DisplayName("dono de conta pessoal FREE não cria chave — 402")
    void freePessoalNaoCria() throws Exception {
        criarChave(novoDono(AccountType.INDIVIDUAL, Plan.FREE))
                .andExpect(status().isPaymentRequired())
                .andExpect(jsonPath("$.message").value("API Keys requerem plano PRO ou Empresa."));
    }

    @Test
    @DisplayName("dono de conta Empresa no FREE não cria chave — 402 (o tipo sai do cadastro)")
    void empresaNoFreeNaoCria() throws Exception {
        criarChave(novoDono(AccountType.COMPANY, Plan.FREE))
                .andExpect(status().isPaymentRequired());
    }

    // ── Controles: plano pago e equipe criam ────────────────────────────────

    @Test
    @DisplayName("dono de conta PRO cria chave — 201")
    void proCria() throws Exception {
        criarChave(novoDono(AccountType.INDIVIDUAL, Plan.PRO))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.plainKey").exists());
    }

    @Test
    @DisplayName("membro de conta ENTERPRISE cria chave — 201 (o plano decide, não o papel)")
    void membroEnterpriseCria() throws Exception {
        AppUser membro = novoUsuario(AccountType.COMPANY, Plan.ENTERPRISE, Role.FREE_EMPLOYEE,
                "apikey-membro-" + UUID.randomUUID() + "@example.com");
        criarChave(membro).andExpect(status().isCreated());
    }

    @Test
    @DisplayName("equipe da plataforma com conta FREE cria chave — 201")
    void equipeCria() throws Exception {
        AppUser staff = userRepository.findByEmail(STAFF)
                .orElseGet(() -> novoUsuario(AccountType.INDIVIDUAL, Plan.FREE, Role.OWNER, STAFF));
        criarChave(staff).andExpect(status().isCreated());
    }

    // ── Decisão do dono: chave que já existe continua valendo ───────────────

    @Test
    @DisplayName("conta que volta para o FREE: a chave antiga autentica e é revogável; chave nova não")
    void chaveAntigaSobreviveAoRebaixamento() throws Exception {
        AppUser user = novoDono(AccountType.INDIVIDUAL, Plan.PRO);
        JsonNode criada = json.readTree(criarChave(user)
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString());
        String chave = criada.get("plainKey").asText();
        String id    = criada.get("id").asText();

        Account conta = user.getAccount();
        conta.setPlan(Plan.FREE);
        accountRepository.save(conta);

        // Autentica e lista (o filtro carrega o usuário de novo a cada requisição,
        // então ele já chega com a conta no FREE).
        mvc.perform(get("/api-keys").header(ApiKeyAuthFilter.HEADER, chave))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").value(id));

        criarChave(user).andExpect(status().isPaymentRequired());

        mvc.perform(delete("/api-keys/" + id)
                        .header("Authorization", "Bearer " + jwtUtil.generateToken(user)))
                .andExpect(status().isNoContent());
    }
}
