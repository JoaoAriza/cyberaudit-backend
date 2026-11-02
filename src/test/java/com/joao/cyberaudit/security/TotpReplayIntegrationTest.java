package com.joao.cyberaudit.security;

import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.AccountType;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.Plan;
import com.joao.cyberaudit.model.Role;
import com.joao.cyberaudit.repository.AccountRepository;
import com.joao.cyberaudit.repository.AppUserRepository;
import com.joao.cyberaudit.service.TotpService;
import com.joao.cyberaudit.service.TwoFactorService;
import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.HashingAlgorithm;
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
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Um código TOTP vale UMA vez (BUG-04).
 *
 * O {@code POST /auth/2fa/verify} validava o código e não o marcava como usado: o mesmo
 * código, com o mesmo token pré-auth, emitia uma sessão nova a cada chamada enquanto
 * estivesse na janela (±30s). Quem visse um código (ombro, phishing, log, proxy)
 * cunhava sessões com ele. O RFC 6238 (§5.2) pede o contrário: depois de aceito, o
 * mesmo OTP não passa de novo.
 *
 * Pela rota real e com a cadeia de filtros, porque a marca de "usado" tem de viver no
 * banco: o filtro recarrega o usuário a cada requisição, e um contador em memória da
 * entidade não sobreviveria a isso. Os códigos são gerados com o mesmo algoritmo do
 * aplicativo autenticador, a partir do relógio de verdade.
 *
 * O teste NÃO é {@code @Transactional}: o consumo é uma UPDATE commitada, e é ela que a
 * requisição seguinte precisa enxergar.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class TotpReplayIntegrationTest {

    @Autowired private MockMvc mvc;
    @Autowired private JwtUtil jwtUtil;
    @Autowired private TotpService totpService;
    @Autowired private TwoFactorService twoFactorService;
    @Autowired private AppUserRepository userRepository;
    @Autowired private AccountRepository accountRepository;

    private final CodeGenerator gerador = new DefaultCodeGenerator(HashingAlgorithm.SHA1);

    private AppUser usuario(boolean totpLigado) {
        Account account = accountRepository.save(Account.builder()
                .type(AccountType.INDIVIDUAL)
                .plan(Plan.FREE)
                .displayName("Conta TOTP")
                .createdAt(LocalDateTime.now())
                .build());
        return userRepository.save(AppUser.builder()
                .name("Cliente TOTP")
                .email("totp-" + UUID.randomUUID() + "@example.com")
                .passwordHash("$2a$04$naoImportaParaEsteTeste000000000000000000000000000000")
                .role(Role.OWNER)
                .active(true)
                .createdAt(LocalDateTime.now())
                .account(account)
                .totpSecret(totpService.generateSecret())
                .totpEnabled(totpLigado)
                .build());
    }

    /** Janela de 30s em que o autenticador está agora — o "contador" do TOTP. */
    private static long passoAtual() {
        return System.currentTimeMillis() / 1000 / 30;
    }

    private String codigo(AppUser user, long passo) throws Exception {
        return gerador.generate(user.getTotpSecret(), passo);
    }

    private ResultActions verifica(String preAuth, String codigo) throws Exception {
        return mvc.perform(post("/auth/2fa/verify")
                .header("Authorization", "Bearer " + preAuth)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"code\":\"" + codigo + "\",\"method\":\"TOTP\"}"));
    }

    @Test
    @DisplayName("mesmo código e mesmo pré-auth: 1ª vez 200, 2ª vez recusada")
    void mesmoCodigoNaoVerificaDuasVezes() throws Exception {
        AppUser user = usuario(true);
        String preAuth = jwtUtil.generatePreAuthToken(user);
        String codigo = codigo(user, passoAtual());

        verifica(preAuth, codigo)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").exists());

        verifica(preAuth, codigo)
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.message", containsString("já utilizado")));
    }

    @Test
    @DisplayName("o código da janela seguinte passa; voltar para um anterior, não")
    void codigoMaisNovoPassaOMaisVelhoNao() throws Exception {
        AppUser user = usuario(true);
        String preAuth = jwtUtil.generatePreAuthToken(user);
        long agora = passoAtual();

        verifica(preAuth, codigo(user, agora)).andExpect(status().isOk());
        // O autenticador adiantado em uma janela ainda é aceito (tolerância de relógio)
        // e é mais novo que o último usado: o bloqueio não pode travar o próximo código.
        verifica(preAuth, codigo(user, agora + 1)).andExpect(status().isOk());
        verifica(preAuth, codigo(user, agora)).andExpect(status().isUnprocessableEntity());
    }

    @Test
    @DisplayName("o mesmo código em pedidos simultâneos: só um passa")
    void pedidosSimultaneosSoUmPassa() throws Exception {
        AppUser user = usuario(true);
        String preAuth = jwtUtil.generatePreAuthToken(user);
        String codigo = codigo(user, passoAtual());

        int pedidos = 6;
        ExecutorService pool = Executors.newFixedThreadPool(pedidos);
        CountDownLatch largada = new CountDownLatch(1);
        List<Future<Integer>> respostas = new ArrayList<>();
        try {
            for (int i = 0; i < pedidos; i++) {
                respostas.add(pool.submit(() -> {
                    largada.await();
                    return verifica(preAuth, codigo).andReturn().getResponse().getStatus();
                }));
            }
            largada.countDown();

            int aceitos = 0;
            for (Future<Integer> resposta : respostas) {
                int status = resposta.get();
                if (status == 200) aceitos++;
                // 429: o throttle de 2FA trava depois de 5 falhas — também é recusa.
                else assertTrue(status == 422 || status == 429, "status inesperado: " + status);
            }
            assertEquals(1, aceitos, "um código, uma sessão");
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    @DisplayName("o código que confirmou a ativação do TOTP não serve para logar")
    void codigoDaAtivacaoNaoServeParaLogin() throws Exception {
        AppUser user = usuario(false);
        long agora = passoAtual();

        twoFactorService.confirmTotpSetup(user, codigo(user, agora));

        String preAuth = jwtUtil.generatePreAuthToken(user);
        verifica(preAuth, codigo(user, agora)).andExpect(status().isUnprocessableEntity());
        // Controle: o TOTP está ligado e o login funciona com um código ainda não usado.
        verifica(preAuth, codigo(user, agora + 1)).andExpect(status().isOk());
    }
}
