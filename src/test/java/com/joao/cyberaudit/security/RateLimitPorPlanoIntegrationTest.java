package com.joao.cyberaudit.security;

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
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Rate limit por minuto pelo plano da conta, de ponta a ponta (BUG-20, cyberaudit-qa).
 *
 * Antes o limite vinha do papel. Todo cadastro sai OWNER, e OWNER não tinha limite: o
 * qa-free (FREE) fez 12 chamadas no mesmo minuto sem um 429. O membro FREE_EMPLOYEE tinha
 * 60 por minuto, mesmo numa conta FREE.
 *
 * O alvo é {@code 127.0.0.1} de propósito. O SsrfGuard recusa com 403 DOMAIN_BLOCKED
 * logo depois do rate limit, então 403 quer dizer "o rate limit deixou passar", 429 quer
 * dizer "barrou", e nenhum teste toca a rede.
 *
 * O balde repõe 1 ficha a cada 60/limite segundos. No FREE (12 s) a 6ª chamada dá 429 com
 * certeza. No PRO (1 s) e no ENTERPRISE (0,5 s), uma rodada lenta de MockMvc pode ganhar
 * 1 ou 2 fichas no meio. Por isso esses afirmam que as N primeiras passam e que o 429
 * chega logo depois, dentro de {@link #FOLGA}. No código antigo o 429 não chegava nunca.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestPropertySource(properties = "platform.staff-emails=" + RateLimitPorPlanoIntegrationTest.STAFF)
class RateLimitPorPlanoIntegrationTest {

    static final String STAFF = "equipe-rl@cyberaudit.test";

    /** Fichas que uma rodada lenta pode ganhar no PRO e no ENTERPRISE. */
    private static final int FOLGA = 20;

    @Autowired private MockMvc mvc;
    @Autowired private JwtUtil jwtUtil;
    @Autowired private AppUserRepository userRepository;
    @Autowired private AccountRepository accountRepository;
    @Autowired private PlanLimitService planLimitService;

    private AppUser novoUsuario(String email, AccountType tipo, Plan plano, Role papel) {
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

    private static String emailNovo() {
        return "rl-" + UUID.randomUUID() + "@example.com";
    }

    /** Dono de conta pessoal, como sai do cadastro. */
    private AppUser novoDono(Plan plano) {
        return novoUsuario(emailNovo(), AccountType.INDIVIDUAL, plano, Role.OWNER);
    }

    private AppUser novoMembro(Plan plano, Role papel) {
        return novoUsuario(emailNovo(), AccountType.COMPANY, plano, papel);
    }

    private MockHttpServletRequestBuilder verifyCheck(AppUser user) {
        MockHttpServletRequestBuilder req = get("/scan/verify-check").param("host", "127.0.0.1");
        return user == null ? req : req.header("Authorization", "Bearer " + jwtUtil.generateToken(user));
    }

    /**
     * Chama o verify-check até o primeiro 429 e devolve a posição dele (a 1ª chamada é a 1).
     * Toda chamada antes do 429 tem de ser 403 (passou o rate limit). Sem 429 até
     * {@code teto}, falha.
     */
    private int primeiro429(AppUser user, int teto) throws Exception {
        for (int i = 1; i <= teto; i++) {
            int status = mvc.perform(verifyCheck(user)).andReturn().getResponse().getStatus();
            if (status == 429) return i;
            assertEquals(403, status, "chamada " + i + " deveria ter passado o rate limit");
        }
        return fail("nenhum 429 em " + teto + " chamadas no mesmo minuto");
    }

    /** As {@code limite} primeiras passam, e o 429 vem logo depois. */
    private void limiteNoMinuto(AppUser user, int limite) throws Exception {
        int posicao = primeiro429(user, limite + FOLGA);
        assertTrue(posicao > limite,
                "o 429 veio na chamada " + posicao + ", antes do limite de " + limite);
    }

    // ── Limite pelo plano, não pelo papel ───────────────────────────────────

    @Test
    @DisplayName("dono de conta FREE (o qa-free): a 6ª chamada no minuto dá 429")
    void donoFree() throws Exception {
        assertEquals(RateLimitService.FREE_RPM + 1, primeiro429(novoDono(Plan.FREE), 15));
    }

    @Test
    @DisplayName("membro FREE_EMPLOYEE de conta FREE: a 6ª dá 429 (antes eram 60)")
    void membroDeContaFree() throws Exception {
        assertEquals(RateLimitService.FREE_RPM + 1,
                primeiro429(novoMembro(Plan.FREE, Role.FREE_EMPLOYEE), 15));
    }

    @Test
    @DisplayName("dono de conta PRO: 60 por minuto, depois 429")
    void donoPro() throws Exception {
        limiteNoMinuto(novoDono(Plan.PRO), RateLimitService.PRO_RPM);
    }

    @Test
    @DisplayName("membro FREE_EMPLOYEE de conta ENTERPRISE: 120 por minuto (antes eram 60)")
    void membroDeContaEnterprise() throws Exception {
        limiteNoMinuto(novoMembro(Plan.ENTERPRISE, Role.FREE_EMPLOYEE), RateLimitService.ENTERPRISE_RPM);
    }

    @Test
    @DisplayName("FREE que esgotou o minuto e assina o PRO volta a passar na hora")
    void upgradeTrocaDeBalde() throws Exception {
        AppUser user = novoDono(Plan.FREE);
        assertEquals(RateLimitService.FREE_RPM + 1, primeiro429(user, 15));

        Account conta = user.getAccount();
        conta.setPlan(Plan.PRO);
        accountRepository.save(conta);

        mvc.perform(verifyCheck(user)).andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("no /scan, o 429 vem antes da cota: a 6ª chamada do FREE não gasta scan")
    void scanBarraAntesDaCota() throws Exception {
        AppUser user = novoDono(Plan.FREE);
        String token = "Bearer " + jwtUtil.generateToken(user);
        for (int i = 1; i <= RateLimitService.FREE_RPM; i++) {
            mvc.perform(get("/scan").param("url", "http://127.0.0.1/").header("Authorization", token))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.error").value("DOMAIN_BLOCKED"));
        }
        mvc.perform(get("/scan").param("url", "http://127.0.0.1/").header("Authorization", token))
                .andExpect(status().isTooManyRequests());

        assertEquals(Plan.FREE.dailyScanLimit - RateLimitService.FREE_RPM,
                planLimitService.getRemainingScans(user));
    }

    // ── Isenção e controles ─────────────────────────────────────────────────

    @Test
    @DisplayName("equipe da plataforma fica isenta: 130 chamadas no minuto, nenhum 429")
    void equipeIsenta() throws Exception {
        AppUser staff = novoUsuario(STAFF, AccountType.INDIVIDUAL, Plan.FREE, Role.OWNER);
        for (int i = 1; i <= 130; i++) {
            assertEquals(403, mvc.perform(verifyCheck(staff)).andReturn().getResponse().getStatus(),
                    "chamada " + i);
        }
    }

    @Test
    @DisplayName("controle: visitante continua com 5 por minuto, por IP")
    void visitante() throws Exception {
        String ip = "198.51.100." + (1 + (int) (Math.random() * 250));
        for (int i = 1; i <= RateLimitService.GUEST_RPM; i++) {
            mvc.perform(verifyCheck(null).with(r -> { r.setRemoteAddr(ip); return r; }))
                    .andExpect(status().isForbidden());
        }
        mvc.perform(verifyCheck(null).with(r -> { r.setRemoteAddr(ip); return r; }))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.message").value(
                        "Muitas requisições. Limite de 5 requests/min para visitantes."));
    }
}
