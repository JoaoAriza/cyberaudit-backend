package com.joao.cyberaudit.controller;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Forma do JSON de GET /billing/plans.
 *
 * O conteúdo do cardápio é coberto por PlanCatalogServiceTest; aqui trava o
 * CONTRATO — os nomes de campo contra os quais o Frontend programa. Renomear
 * `state` ou `limit` quebra a tela de planos silenciosamente, e o TypeScript não
 * pega isso: ele confia no tipo que a gente declarou, não no que a API devolve.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class BillingPlansEndpointTest {

    @Autowired
    private MockMvc mvc;

    @Test
    @DisplayName("devolve os três planos com os campos que o Frontend consome")
    void formaDoCardapio() throws Exception {
        mvc.perform(get("/billing/plans"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(3))
                .andExpect(jsonPath("$[0].plan").value("FREE"))
                .andExpect(jsonPath("$[0].amount").doesNotExist())   // FREE não se assina
                .andExpect(jsonPath("$[1].plan").value("PRO"))
                .andExpect(jsonPath("$[1].amount").value(29.90))
                .andExpect(jsonPath("$[1].currency").value("BRL"))
                .andExpect(jsonPath("$[2].plan").value("ENTERPRISE"))
                .andExpect(jsonPath("$[2].amount").value(99.90));
    }

    @Test
    @DisplayName("cada recurso traz id e state; quantidade vem em limit")
    void formaDoRecurso() throws Exception {
        mvc.perform(get("/billing/plans"))
                .andExpect(status().isOk())
                // O ◑ da tela: o Pro entrega laudo, mas só no domínio dele.
                .andExpect(jsonPath("$[1].features[?(@.id == 'PDF_EXPORT')].state")
                        .value("VERIFIED_DOMAINS_ONLY"))
                .andExpect(jsonPath("$[2].features[?(@.id == 'PDF_EXPORT')].state")
                        .value("YES"))
                // -1 = ilimitado, e é o Frontend que decide como escrever isso.
                .andExpect(jsonPath("$[0].features[?(@.id == 'DAILY_SCANS')].limit").value(10))
                .andExpect(jsonPath("$[1].features[?(@.id == 'DAILY_SCANS')].limit").value(-1));
    }
}
