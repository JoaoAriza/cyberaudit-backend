package com.joao.cyberaudit.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Instante que sai na API tem de dizer em que fuso está.
 *
 * O bug que originou isto: o painel admin mostrava os eventos três horas no
 * futuro para quem estava no Brasil. A hora gravada estava certa (UTC) — o que
 * faltava era o "Z" no JSON, sem o qual o navegador lê a data como hora local.
 *
 * O teste sobe a auto-configuração REAL do Jackson junto com o TimeConfig: o
 * ponto em risco é justamente a precedência entre o serializador do JavaTimeModule
 * e o nosso, e um ObjectMapper montado à mão no teste não provaria nada sobre
 * isso.
 */
class TimeConfigTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(JacksonAutoConfiguration.class))
            .withUserConfiguration(TimeConfig.class);

    @Test
    @DisplayName("LocalDateTime sai como instante UTC explícito, não como hora solta")
    void carimbaUtcNaSaida() {
        runner.run(ctx -> {
            ObjectMapper mapper = ctx.getBean(ObjectMapper.class);

            String json = mapper.writeValueAsString(
                    Map.of("timestamp", LocalDateTime.of(2026, 9, 8, 12, 24, 58)));

            assertEquals("{\"timestamp\":\"2026-09-08T12:24:58Z\"}", json);
        });
    }

    @Test
    @DisplayName("o que sai é parseável como instante — é isso que o navegador faz")
    void saidaEhInstanteValido() {
        runner.run(ctx -> {
            ObjectMapper mapper = ctx.getBean(ObjectMapper.class);

            String json = mapper.writeValueAsString(LocalDateTime.of(2026, 9, 8, 12, 24, 58));
            String iso  = json.replace("\"", "");

            assertEquals(Instant.parse("2026-09-08T12:24:58Z"), Instant.parse(iso));
            assertTrue(iso.endsWith("Z"), "sem o Z o navegador interpreta como hora local: " + iso);
        });
    }
}
