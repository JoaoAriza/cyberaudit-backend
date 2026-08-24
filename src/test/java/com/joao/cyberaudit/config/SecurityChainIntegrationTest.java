package com.joao.cyberaudit.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * A cadeia de filtros de segurança, subida de verdade.
 *
 * O que falhou em produção: o preflight de CORS voltava 403. A configuração de
 * CORS estava certa — o problema era ela estar registrada no MVC, atrás do Spring
 * Security, então o OPTIONS (que o navegador manda SEM credencial) era julgado
 * pelas regras de autorização e barrado antes de chegar nela. O front só via
 * "Network Error", e custou uma rodada inteira de investigação.
 *
 * {@link CorsConfigTest} cobre o conteúdo da configuração em unidade e diz, no
 * próprio comentário, que ordem de filtro "só um teste que suba a cadeia inteira
 * pega". Esta é essa classe.
 *
 * Por isso os testes daqui afirmam sobre STATUS e CABEÇALHO, nunca sobre corpo:
 * o que está sob teste é quem responde primeiro, não o que o controller devolve.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SecurityChainIntegrationTest {

    /** Precisa bater com cors.allowed-origins do application-test.properties. */
    private static final String ORIGEM_PERMITIDA = "http://localhost:5173";

    @Autowired
    private MockMvc mvc;

    // ── A regressão ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("preflight em rota autenticada passa sem credencial — a regressão do 403")
    void preflightEmRotaAutenticadaNaoEBarrado() throws Exception {
        // /billing/** é `.authenticated()`. O preflight chega sem Authorization,
        // porque o navegador nunca manda credencial no OPTIONS: é exatamente a
        // combinação que voltava 403 e abortava a requisição real.
        mvc.perform(options("/billing/subscription")
                        .header("Origin", ORIGEM_PERMITIDA)
                        .header("Access-Control-Request-Method", "GET")
                        .header("Access-Control-Request-Headers", "authorization"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", ORIGEM_PERMITIDA));
    }

    @Test
    @DisplayName("preflight libera o header Authorization — sem ele todo endpoint logado quebra")
    void preflightLiberaAuthorization() throws Exception {
        mvc.perform(options("/history/scans")
                        .header("Origin", ORIGEM_PERMITIDA)
                        .header("Access-Control-Request-Method", "GET")
                        .header("Access-Control-Request-Headers", "authorization"))
                .andExpect(status().isOk())
                .andExpect(header().stringValues("Access-Control-Allow-Headers",
                        org.hamcrest.Matchers.hasItem(
                                org.hamcrest.Matchers.containsStringIgnoringCase("authorization"))));
    }

    @Test
    @DisplayName("origem desconhecida não ganha permissão no preflight")
    void preflightDeOrigemEstranhaNaoPassa() throws Exception {
        mvc.perform(options("/billing/subscription")
                        .header("Origin", "https://site-de-terceiro.example")
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(status().isForbidden())
                .andExpect(header().doesNotExist("Access-Control-Allow-Origin"));
    }

    // ── Rotas fechadas continuam fechadas ────────────────────────────────────

    @Test
    @DisplayName("rota autenticada sem token responde 401")
    void rotaAutenticadaExigeToken() throws Exception {
        mvc.perform(get("/billing/subscription")).andExpect(status().isUnauthorized());
        mvc.perform(get("/history/scans")).andExpect(status().isUnauthorized());
        mvc.perform(get("/domains")).andExpect(status().isUnauthorized());
        mvc.perform(get("/account/me")).andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("/admin/** sem token responde 401, não 403 vazando que a rota existe")
    void adminExigeToken() throws Exception {
        mvc.perform(get("/admin/users")).andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("token inválido é recusado — o filtro JWT não engole lixo")
    void tokenInvalidoNaoAutentica() throws Exception {
        mvc.perform(get("/billing/subscription")
                        .header("Authorization", "Bearer nao-e-um-jwt"))
                .andExpect(status().isUnauthorized());
    }

    // ── Rotas públicas continuam públicas ────────────────────────────────────

    @Test
    @DisplayName("health check é público")
    void healthEPublico() throws Exception {
        mvc.perform(get("/actuator/health")).andExpect(status().isOk());
    }

    @Test
    @DisplayName("webhook do MP é público — o Mercado Pago não tem como se autenticar")
    void webhookEPublico() throws Exception {
        // Sem `permitAll` aqui o MP levaria 401 e reenviaria em laço. O controller
        // recusa o corpo vazio por conta própria e responde 200 para não gerar
        // reenvio — o que importa é ter chegado nele.
        mvc.perform(post("/billing/webhook").contentType("application/json").content("{}"))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("cardápio de planos é público — visitante precisa vê-lo antes de ter conta")
    void cardapioEPublico() throws Exception {
        // Fica sob /billing/**, que é `.authenticated()`. Sem a exceção explícita
        // no SecurityConfig, a tela de planos ficaria invisível para quem não tem
        // conta — justamente o público que ela existe para converter.
        mvc.perform(get("/billing/plans")).andExpect(status().isOk());
    }

    @Test
    @DisplayName("rota pública chega no controller — 400 por parâmetro faltando, não 401")
    void rotaPublicaChegaNoController() throws Exception {
        // /scan/verify-check é permitAll e exige o parâmetro `host`. O 400 do MVC
        // é a prova de que a requisição atravessou a autorização: chain barrando
        // responderia antes, sem nunca olhar os parâmetros.
        mvc.perform(get("/scan/verify-check")).andExpect(status().isBadRequest());
    }
}
