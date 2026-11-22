package com.joao.cyberaudit.service;

import com.joao.cyberaudit.exception.TargetUnreachableException;
import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.AccountType;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.Plan;
import com.joao.cyberaudit.model.Role;
import com.joao.cyberaudit.model.SSLInfo;
import com.joao.cyberaudit.model.ScanOrigin;
import com.joao.cyberaudit.repository.AccountRepository;
import com.joao.cyberaudit.repository.AppUserRepository;
import com.joao.cyberaudit.security.JwtUtil;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Set;
import java.util.UUID;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Alvo que não existe ou não responde fica sem laudo e sem nota.
 *
 * Regressão do BUG-16 (cyberaudit-qa). Um domínio digitado errado saía com 17/100,
 * CRITICAL, e um host sem nada escutando saía com 29/100, HIGH: 14 módulos marcavam "OK"
 * sem terem falado com ninguém. Decisões do dono (2026-11-22):
 * - domínio que não resolve: 422 {@code TARGET_NOT_FOUND}, antes de gastar cota;
 * - resolve, mas nada aceita conexão nem em http nem em https: 422
 *   {@code TARGET_UNREACHABLE}. Aqui a cota já foi gasta: só se descobre tentando conectar.
 *
 * Nada daqui sai da máquina. O domínio é {@code .invalid} (RFC 6761: nunca resolve). O
 * alvo que responde é um servidor HTTP em 127.0.0.1, liberado no SsrfGuard só durante a
 * classe, e a porta fechada é uma porta aberta e logo fechada.
 *
 * O {@code CookieSecurityService} roda logo depois da checagem de conexão, e aqui é um
 * mock que lança {@link PassouDaChecagem}. Então "lançou PassouDaChecagem" quer dizer "o
 * alvo respondeu e o scan seguiu para a análise", e o resto do scan não roda. No código
 * antigo é ele que aparece onde hoje sai o 422 (como 500).
 *
 * O {@code SSLService} também é mock e devolve "https sem certificado válido", o mesmo que
 * o de verdade devolve quando o handshake falha. O de verdade ficaria até 8 s pendurado
 * no handshake contra o servidor de teste, que só fala http. O caminho do bug não passa
 * por ele: quem decide se o alvo respondeu é o fetch de http e de https.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AlvoInacessivelIntegrationTest {

    /** Sinal de que o alvo respondeu e o scan seguiu para a análise. */
    static class PassouDaChecagem extends RuntimeException {
        PassouDaChecagem() { super("o alvo respondeu: o scan seguiu para a análise"); }
    }

    private static final String NAO_RESOLVE = "http://nao-existe-qa.invalid/";

    @MockitoBean private CookieSecurityService cookieSecurityService;
    @MockitoBean private SSLService sslService;

    @Autowired private MockMvc mvc;
    @Autowired private JwtUtil jwtUtil;
    @Autowired private ScanOrchestrator orchestrator;
    @Autowired private PlanLimitService planLimitService;
    @Autowired private AccountRepository accountRepository;
    @Autowired private AppUserRepository userRepository;

    private HttpServer servidor;

    @BeforeEach
    void prepara() {
        SsrfGuard.setTestAllowlist(Set.of("127.0.0.1"));
        when(cookieSecurityService.analyze(any())).thenThrow(new PassouDaChecagem());
        when(sslService.checkSSL(anyString()))
                .thenReturn(new SSLInfo(true, false, null, 0, "handshake falhou (mock do teste)"));
    }

    @AfterEach
    void limpa() {
        SsrfGuard.setTestAllowlist(Set.of());
        if (servidor != null) servidor.stop(0);
    }

    private AppUser novoDono(Plan plano) {
        Account conta = accountRepository.save(Account.builder()
                .type(AccountType.INDIVIDUAL)
                .plan(plano)
                .displayName("Conta alvo " + UUID.randomUUID())
                .createdAt(LocalDateTime.now())
                .build());
        return userRepository.save(AppUser.builder()
                .name("Cliente alvo")
                .email("alvo-" + UUID.randomUUID() + "@example.com")
                .passwordHash("$2a$04$naoImportaParaEsteTeste000000000000000000000000000000")
                .role(Role.OWNER)
                .active(true)
                .createdAt(LocalDateTime.now())
                .account(conta)
                .build());
    }

    private String bearer(AppUser user) {
        return "Bearer " + jwtUtil.generateToken(user);
    }

    /** Porta de 127.0.0.1 em que nada escuta: abre, anota o número e fecha. */
    private static int portaFechada() throws IOException {
        try (ServerSocket socket = new ServerSocket()) {
            socket.bind(new InetSocketAddress("127.0.0.1", 0));
            return socket.getLocalPort();
        }
    }

    /** Servidor em 127.0.0.1 que responde a qualquer caminho com o status pedido. */
    private String alvoQueResponde(int status) throws IOException {
        servidor = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        servidor.createContext("/", troca -> {
            byte[] corpo = "<html><body>ok</body></html>".getBytes(StandardCharsets.UTF_8);
            troca.getResponseHeaders().set("Content-Type", "text/html");
            troca.sendResponseHeaders(status, corpo.length);
            troca.getResponseBody().write(corpo);
            troca.close();
        });
        servidor.start();
        return "http://127.0.0.1:" + servidor.getAddress().getPort() + "/";
    }

    // ── Domínio que não resolve: recusado antes da cota ─────────────────────

    @Test
    @DisplayName("domínio que não resolve: /scan dá 422 TARGET_NOT_FOUND e não gasta a cota")
    void naoResolveLeva422SemGastarCota() throws Exception {
        AppUser user = novoDono(Plan.FREE);
        for (int i = 0; i < Plan.FREE.dailyScanLimit - 1; i++) {
            planLimitService.checkAndIncrementDailyScan(user);
        }

        mvc.perform(get("/scan").param("url", NAO_RESOLVE).header("Authorization", bearer(user)))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error").value("TARGET_NOT_FOUND"))
                .andExpect(jsonPath("$.host").value("nao-existe-qa.invalid"))
                .andExpect(jsonPath("$.message").value(containsString("nao-existe-qa.invalid")));

        // Sobrava 1 antes da recusa, e continua sobrando.
        assertDoesNotThrow(() -> planLimitService.checkAndIncrementDailyScan(user),
                "o 422 gastou a última da cota");
        assertThrows(ResponseStatusException.class,
                () -> planLimitService.checkAndIncrementDailyScan(user),
                "controle: depois da última, a cota tem de acabar");
    }

    @Test
    @DisplayName("domínio que não resolve: /scan/async também dá 422, e nenhum scan é aberto")
    void naoResolveNoAsyncLeva422() throws Exception {
        mvc.perform(post("/scan/async").param("url", NAO_RESOLVE)
                        .header("Authorization", bearer(novoDono(Plan.PRO))))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error").value("TARGET_NOT_FOUND"))
                .andExpect(jsonPath("$.scanId").doesNotExist());
    }

    @Test
    @DisplayName("a mensagem do 422 sai no idioma pedido")
    void naoResolveEmIngles() throws Exception {
        mvc.perform(get("/scan").param("url", NAO_RESOLVE).param("lang", "en")
                        .header("Authorization", bearer(novoDono(Plan.PRO))))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.message").value(
                        "The domain nao-existe-qa.invalid was not found in DNS. Check the address you typed."));
    }

    @Test
    @DisplayName("o agendador, que chama o motor direto, também recusa o domínio que não resolve")
    void motorRecusaNaoResolve() {
        TargetUnreachableException e = assertThrows(TargetUnreachableException.class,
                () -> orchestrator.execute(NAO_RESOLVE, false, null, false, ScanOrigin.SCHEDULED));
        assertEquals(TargetUnreachableException.NAO_RESOLVE, e.getCodigo());
        assertEquals("nao-existe-qa.invalid", e.getHost());
    }

    @Test
    @DisplayName("controle: nome que o SsrfGuard bloqueia continua 403, mesmo sem resolver")
    void nomeBloqueadoContinua403() throws Exception {
        // Os dois não resolvem aqui. Sem a ressalva no ScanTargetService, sairiam como
        // "domínio não encontrado" (422). O SSRF-03 do cyberaudit-qa espera 403 no segundo.
        for (String alvo : new String[]{"http://metadata.google.internal/", "http://2130706433/"}) {
            mvc.perform(get("/scan").param("url", alvo).header("Authorization", bearer(novoDono(Plan.PRO))))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.error").value("DOMAIN_BLOCKED"));
        }
    }

    // ── Resolve, mas nada aceita conexão ─────────────────────────────────────

    @Test
    @DisplayName("porta fechada: /scan dá 422 TARGET_UNREACHABLE, e a mensagem não tem 'null'")
    void portaFechadaLeva422() throws Exception {
        String alvo = "http://127.0.0.1:" + portaFechada() + "/";

        mvc.perform(get("/scan").param("url", alvo).header("Authorization", bearer(novoDono(Plan.PRO))))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error").value("TARGET_UNREACHABLE"))
                .andExpect(jsonPath("$.host").value("127.0.0.1"))
                .andExpect(jsonPath("$.message").value(containsString("127.0.0.1")))
                .andExpect(jsonPath("$.message").value(not(containsString("null"))));
    }

    @Test
    @DisplayName("controle: alvo que responde 200 passa da checagem e segue para a análise")
    void alvoQueRespondeSegue() throws Exception {
        String alvo = alvoQueResponde(200);
        assertThrows(PassouDaChecagem.class, () -> orchestrator.execute(alvo, false, null, false));
    }

    @Test
    @DisplayName("controle: alvo que responde com erro (503) também tem o que auditar")
    void alvoQueRespondeComErroSegue() throws Exception {
        String alvo = alvoQueResponde(503);
        assertThrows(PassouDaChecagem.class, () -> orchestrator.execute(alvo, false, null, false));
    }
}
