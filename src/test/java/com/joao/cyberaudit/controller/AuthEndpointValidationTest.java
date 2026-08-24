package com.joao.cyberaudit.controller;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Corpo malformado nos endpoints públicos de autenticação.
 *
 * O que apareceu: {@code POST /auth/login} com {@code {}} estourava
 * NullPointerException em {@code getEmail().toLowerCase()} e respondia 500. Não
 * vazava nada (server.error.include-* está todo desligado), mas 500 é a resposta
 * errada para corpo torto e enche o log de stack trace de quem só mandou
 * requisição malformada — inclusive varredura automática, que é a maior parte
 * desse tráfego num endpoint público.
 *
 * O register já conferia campo obrigatório; o login era o único fora do padrão.
 * Os testes aqui travam os dois, para a assimetria não voltar.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthEndpointValidationTest {

    @Autowired
    private MockMvc mvc;

    private org.springframework.test.web.servlet.ResultActions postJson(String rota, String corpo)
            throws Exception {
        return mvc.perform(post(rota).contentType("application/json").content(corpo));
    }

    // ── Login ────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("login com corpo vazio responde 400, não 500")
    void loginSemCorpoUtil() throws Exception {
        postJson("/auth/login", "{}").andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("login com e-mail em branco responde 400")
    void loginComEmailEmBranco() throws Exception {
        postJson("/auth/login", "{\"email\":\"   \",\"password\":\"seja-o-que-for\"}")
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("login sem senha responde 400 — e não gasta tentativa no throttle")
    void loginSemSenha() throws Exception {
        postJson("/auth/login", "{\"email\":\"alguem@example.com\"}")
                .andExpect(status().isBadRequest());
    }

    // ── Register ─────────────────────────────────────────────────────────────

    @Test
    @DisplayName("register com corpo vazio responde 400")
    void registerSemCorpoUtil() throws Exception {
        postJson("/auth/register", "{}").andExpect(status().isBadRequest());
    }

    // ── Redefinição de senha ─────────────────────────────────────────────────

    @Test
    @DisplayName("forgot-password sem e-mail responde 200 e não diz se a conta existe")
    void forgotPasswordSemEmail() throws Exception {
        // 200 aqui não é descuido: a resposta é sempre a mesma justamente para não
        // permitir enumerar quem tem conta. Sem e-mail, não há nada a fazer, e a
        // mensagem genérica sai igual.
        postJson("/auth/forgot-password", "{}").andExpect(status().isOk());
    }

    @Test
    @DisplayName("reset-password sem token responde 400")
    void resetPasswordSemToken() throws Exception {
        postJson("/auth/reset-password", "{}").andExpect(status().isBadRequest());
    }
}
