package com.joao.cyberaudit.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.AccountType;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.Plan;
import com.joao.cyberaudit.model.Role;
import com.joao.cyberaudit.repository.AccountRepository;
import com.joao.cyberaudit.repository.AppUserRepository;
import com.joao.cyberaudit.service.PlanLimitService;
import com.joao.cyberaudit.service.RateLimitService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.hamcrest.Matchers.startsWith;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * O gate de CI ({@code GET /api-keys/ci}) passa pelas mesmas travas do {@code /scan}.
 *
 * Regressão do BUG-19 (cyberaudit-qa): o gate chamava o orchestrator direto e pulava a
 * cota diária, o rate limit e a trava de plano do scan ativo. Uma chave de conta FREE
 * (chave antiga, que continua valendo depois do BUG-18) rodava scan sem limite.
 *
 * O alvo é {@code http://127.0.0.1/} de propósito: o SsrfGuard do orchestrator recusa
 * com 403 DOMAIN_BLOCKED antes de qualquer requisição de saída. Então "403 DOMAIN_BLOCKED"
 * quer dizer "passou pelas travas e chegou ao scan", e nenhum teste toca a rede.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class ApiKeyCiGateLimitesIntegrationTest {

    private static final String ALVO = "http://127.0.0.1/";

    @Autowired private MockMvc mvc;
    @Autowired private JwtUtil jwtUtil;
    @Autowired private AppUserRepository userRepository;
    @Autowired private AccountRepository accountRepository;
    @Autowired private PlanLimitService planLimitService;
    @Autowired private ObjectMapper json;

    private AppUser novoUsuario(AccountType tipo, Plan plano, Role papel) {
        Account account = accountRepository.save(Account.builder()
                .type(tipo)
                .plan(plano)
                .displayName("Conta " + tipo + " " + plano)
                .createdAt(LocalDateTime.now())
                .build());
        return userRepository.save(AppUser.builder()
                .name("Cliente " + plano)
                .email("ci-gate-" + UUID.randomUUID() + "@example.com")
                .passwordHash("$2a$04$naoImportaParaEsteTeste000000000000000000000000000000")
                .role(papel)
                .active(true)
                .createdAt(LocalDateTime.now())
                .account(account)
                .build());
    }

    /** Dono de conta pessoal, como sai do cadastro. */
    private AppUser novoDono(Plan plano) {
        return novoUsuario(AccountType.INDIVIDUAL, plano, Role.OWNER);
    }

    /** Gasta a cota do dia direto no serviço, sem rodar scan nenhum. */
    private void gastarCota(AppUser user, int quantos) {
        for (int i = 0; i < quantos; i++) planLimitService.checkAndIncrementDailyScan(user);
    }

    private ResultActions gate(AppUser user, boolean ativo) throws Exception {
        return mvc.perform(get("/api-keys/ci")
                .param("url", ALVO)
                .param("threshold", "10")
                .param("active", String.valueOf(ativo))
                .header("Authorization", "Bearer " + jwtUtil.generateToken(user)));
    }

    // ── Cota diária ─────────────────────────────────────────────────────────

    @Test
    @DisplayName("chave antiga de conta FREE com a cota do dia gasta — gate dá 402")
    void chaveFreeComCotaGastaLeva402() throws Exception {
        // O caminho do bug: chave criada no PRO, conta rebaixada para o FREE.
        AppUser user = novoDono(Plan.PRO);
        String chave = json.readTree(mvc.perform(post("/api-keys")
                        .header("Authorization", "Bearer " + jwtUtil.generateToken(user))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"CI\"}"))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString()).get("plainKey").asText();

        Account conta = user.getAccount();
        conta.setPlan(Plan.FREE);
        accountRepository.save(conta);
        gastarCota(user, Plan.FREE.dailyScanLimit);

        mvc.perform(get("/api-keys/ci").param("url", ALVO).param("threshold", "10")
                        .header(ApiKeyAuthFilter.HEADER, chave))
                .andExpect(status().isPaymentRequired())
                .andExpect(jsonPath("$.message").value(startsWith("Limite diário de 10 scans atingido.")));
    }

    @Test
    @DisplayName("o gate conta na mesma cota do /scan — gastou a última, o /scan dá 402")
    void gateContaNaMesmaCotaDoScan() throws Exception {
        AppUser user = novoDono(Plan.FREE);
        gastarCota(user, Plan.FREE.dailyScanLimit - 1);

        // Sobra 1: o gate passa pelas travas, gasta a última e chega ao scan.
        gate(user, false)
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("DOMAIN_BLOCKED"));

        mvc.perform(get("/scan").param("url", ALVO)
                        .header("Authorization", "Bearer " + jwtUtil.generateToken(user)))
                .andExpect(status().isPaymentRequired());
    }

    // ── Trava de plano do scan ativo ────────────────────────────────────────

    @Test
    @DisplayName("conta pessoal FREE pedindo ativo — gate dá 402 de plano, como o /scan")
    void freeAtivoLeva402DePlano() throws Exception {
        gate(novoDono(Plan.FREE), true)
                .andExpect(status().isPaymentRequired())
                .andExpect(jsonPath("$.message").value("Scan ativo requer plano PRO ou superior."));
    }

    @Test
    @DisplayName("conta PRO pedindo ativo fora de domínio verificado na conta — 403 ACCOUNT_DOMAIN_NOT_VERIFIED")
    void proAtivoSemDominioNaContaLevaTravaDeConta() throws Exception {
        gate(novoDono(Plan.PRO), true)
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("ACCOUNT_DOMAIN_NOT_VERIFIED"));
    }

    // ── Rate limit por minuto ───────────────────────────────────────────────

    @Test
    @DisplayName("membro de conta FREE (5/min) — a 6ª chamada no minuto dá 429")
    void rateLimitValeNoGate() throws Exception {
        // O limite segue o plano da conta (BUG-20). O FREE tem 5 por minuto e 10 scans por
        // dia: as 5 primeiras passam (403 DOMAIN_BLOCKED) e a 6ª é barrada antes da cota.
        AppUser membro = novoUsuario(AccountType.COMPANY, Plan.FREE, Role.FREE_EMPLOYEE);
        for (int i = 0; i < RateLimitService.FREE_RPM; i++) {
            gate(membro, false).andExpect(status().isForbidden());
        }
        gate(membro, false).andExpect(status().isTooManyRequests());
    }

    // ── Controle ────────────────────────────────────────────────────────────

    @Test
    @DisplayName("conta PRO, passivo — passa pelas travas e chega ao scan")
    void proPassivoChegaAoScan() throws Exception {
        gate(novoDono(Plan.PRO), false)
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("DOMAIN_BLOCKED"));
    }
}
