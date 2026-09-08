package com.joao.cyberaudit.config;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import org.springframework.boot.autoconfigure.jackson.Jackson2ObjectMapperBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

/**
 * Carimba o fuso nos instantes que saem na API.
 *
 * O sistema guarda tudo em {@code LocalDateTime} — que não carrega fuso nenhum.
 * Serializado como estava, o Jackson escrevia {@code "2026-09-08T12:24:58"}, e o
 * {@code new Date()} do navegador lê data SEM fuso como hora LOCAL de quem está
 * olhando. O valor era UTC (o contêiner do Render roda em UTC), então o painel
 * admin mostrava 12:24 para um evento que aconteceu às 09:24 em São Paulo: três
 * horas no futuro, com cara de dado correto.
 *
 * Escrevendo {@code "2026-09-08T12:24:58Z"} o navegador passa a converter para o
 * fuso de quem abriu a tela — sem que nenhuma das dezenas de chamadas de
 * formatação no Frontend precise saber disso. Quem está na Alemanha vê 14:24,
 * quem está no Brasil vê 09:24, e é o mesmo instante.
 *
 * O contrato depende de {@code LocalDateTime.now()} significar UTC em toda a
 * aplicação — quem garante isso é o pin de fuso da JVM em
 * {@code CyberauditApplication}. Um sem o outro carimba Z em hora que não é UTC,
 * que é pior do que não carimbar nada.
 */
@Configuration
public class TimeConfig {

    @Bean
    public Jackson2ObjectMapperBuilderCustomizer instantesComFusoExplicito() {
        return builder -> builder.serializerByType(LocalDateTime.class, new UtcSerializer());
    }

    static class UtcSerializer extends JsonSerializer<LocalDateTime> {
        @Override
        public void serialize(LocalDateTime valor, JsonGenerator gen, SerializerProvider provider)
                throws IOException {
            gen.writeString(valor.toInstant(ZoneOffset.UTC).toString());
        }
    }
}
