package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.ScheduledScan.Frequency;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A hora do agendamento é a hora de quem agendou.
 *
 * Antes da coluna de fuso, "08:00" era 08:00 UTC para todo mundo — a tela dizia
 * isso em letras miúdas e sobrava para o usuário fazer a conta. O que estes
 * testes fixam é a invariante, não um horário: seja qual for o fuso, o disparo
 * cai na hora escolhida DAQUELE fuso, e o valor gravado é o instante em UTC.
 */
class ScheduledScanTimeZoneTest {

    @Test
    @DisplayName("dispara na hora local do agendamento, em qualquer fuso")
    void horaEhLidaNoFusoDoAgendamento() {
        for (String id : List.of("America/Sao_Paulo", "Europe/Berlin", "Asia/Tokyo",
                                 "Pacific/Kiritimati", "UTC")) {
            ZoneId zona = ZoneId.of(id);

            LocalDateTime emUtc = ScheduledScanService.calcNextRun(Frequency.DAILY, 8, zona);
            int horaLocal = emUtc.atZone(ZoneOffset.UTC).withZoneSameInstant(zona).getHour();

            assertEquals(8, horaLocal, "agendamento em " + id + " deveria disparar às 8h locais");
        }
    }

    @Test
    @DisplayName("agendamento antigo (sem fuso) continua em UTC")
    void utcPermaneceUtc() {
        LocalDateTime emUtc = ScheduledScanService.calcNextRun(
                Frequency.DAILY, 8, UserTimeZoneService.PADRAO);

        assertEquals(8, emUtc.getHour());
    }

    @Test
    @DisplayName("a próxima execução está sempre no futuro")
    void nuncaAgendaNoPassado() {
        for (int hora = 0; hora < 24; hora++) {
            LocalDateTime emUtc = ScheduledScanService.calcNextRun(
                    Frequency.DAILY, hora, ZoneId.of("America/Sao_Paulo"));

            assertTrue(emUtc.isAfter(LocalDateTime.now(ZoneOffset.UTC)),
                    "hora " + hora + " agendou para tras: " + emUtc);
        }
    }

    @Test
    @DisplayName("semanal cai sete dias adiante quando a hora de hoje já passou")
    void semanalEmpurraUmaSemana() {
        ZoneId zona = ZoneId.of("America/Sao_Paulo");

        LocalDateTime diario  = ScheduledScanService.calcNextRun(Frequency.DAILY, 0, zona);
        LocalDateTime semanal = ScheduledScanService.calcNextRun(Frequency.WEEKLY, 0, zona);

        // Meia-noite de hoje já passou em qualquer momento do dia: o diário vai para
        // amanhã e o semanal, para daqui a sete dias.
        assertEquals(diario.plusDays(6).toLocalDate(), semanal.toLocalDate());
    }
}
