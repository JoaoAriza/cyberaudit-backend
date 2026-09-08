package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.repository.AppUserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Fuso do usuário: o que é aceito, quem sobrepõe quem, e onde o dia começa.
 */
class UserTimeZoneServiceTest {

    private final AppUserRepository repo = mock(AppUserRepository.class);
    private final UserTimeZoneService service = new UserTimeZoneService(repo);

    UserTimeZoneServiceTest() {
        when(repo.save(any(AppUser.class))).thenAnswer(inv -> inv.getArgument(0));
    }

    private AppUser usuario() {
        AppUser u = new AppUser();
        u.setName("Teste");
        return u;
    }

    // ── Validação ────────────────────────────────────────────────────────────

    @Test
    @DisplayName("aceita identificador IANA")
    void aceitaIana() {
        AppUser u = service.definir(usuario(), "America/Sao_Paulo", true);
        assertEquals("America/Sao_Paulo", u.getTimezone());
        assertTrue(u.isTimezoneManual());
    }

    @Test
    @DisplayName("recusa offset — descreve um instante, não um lugar, e congela fora do horário de verão")
    void recusaOffset() {
        assertThrows(ResponseStatusException.class, () -> service.definir(usuario(), "-03:00", true));
        assertThrows(ResponseStatusException.class, () -> service.definir(usuario(), "GMT-3", true));
        assertThrows(ResponseStatusException.class, () -> service.definir(usuario(), "UTC-3", true));
    }

    @Test
    @DisplayName("recusa lixo e vazio")
    void recusaInvalido() {
        assertThrows(ResponseStatusException.class, () -> service.definir(usuario(), "Marte/Olympus", true));
        assertThrows(ResponseStatusException.class, () -> service.definir(usuario(), "  ", true));
        assertThrows(ResponseStatusException.class, () -> service.definir(usuario(), null, true));
    }

    // ── Precedência ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("detecção do navegador não atropela escolha do perfil")
    void manualVenceAutomatico() {
        AppUser u = service.definir(usuario(), "America/Sao_Paulo", true);

        service.definir(u, "Europe/Lisbon", false);   // login a partir de outro país

        assertEquals("America/Sao_Paulo", u.getTimezone());
    }

    @Test
    @DisplayName("sem escolha explícita, o navegador manda")
    void automaticoAtualiza() {
        AppUser u = usuario();

        service.definir(u, "America/Sao_Paulo", false);
        service.definir(u, "Europe/Lisbon", false);

        assertEquals("Europe/Lisbon", u.getTimezone());
        assertFalse(u.isTimezoneManual());
    }

    @Test
    @DisplayName("voltar ao automático limpa a escolha")
    void voltaAoAutomatico() {
        AppUser u = service.definir(usuario(), "America/Sao_Paulo", true);

        service.automatico(u);

        assertNull(u.getTimezone());
        assertFalse(u.isTimezoneManual());
    }

    // ── Fuso efetivo ─────────────────────────────────────────────────────────

    @Test
    @DisplayName("sem fuso, ou com fuso que sumiu da base do JDK, cai em UTC sem estourar")
    void zonaDeNuncaLanca() {
        assertEquals(UserTimeZoneService.PADRAO, service.zonaDe(null));
        assertEquals(UserTimeZoneService.PADRAO, service.zonaDe(usuario()));

        AppUser quebrado = usuario();
        quebrado.setTimezone("Marte/Olympus");
        assertEquals(UserTimeZoneService.PADRAO, service.zonaDe(quebrado));
    }

    // ── Corte de dia ─────────────────────────────────────────────────────────

    @Test
    @DisplayName("o dia filtrado é o dia de quem filtra, convertido para UTC")
    void diaCivilDoUsuario() {
        ZoneId sp = ZoneId.of("America/Sao_Paulo");
        LocalDate dia = LocalDate.of(2026, 9, 8);

        // 08/09 00:00 em São Paulo = 08/09 03:00 UTC
        assertEquals(LocalDateTime.of(2026, 9, 8, 3, 0), UserTimeZoneService.inicioDoDia(dia, sp));
        assertEquals(LocalDateTime.of(2026, 9, 9, 2, 59, 59), UserTimeZoneService.fimDoDia(dia, sp));
    }

    @Test
    @DisplayName("em UTC o corte é o dia cheio, como antes")
    void diaCivilEmUtc() {
        LocalDate dia = LocalDate.of(2026, 9, 8);

        assertEquals(LocalDateTime.of(2026, 9, 8, 0, 0),
                UserTimeZoneService.inicioDoDia(dia, UserTimeZoneService.PADRAO));
        assertEquals(LocalDateTime.of(2026, 9, 8, 23, 59, 59),
                UserTimeZoneService.fimDoDia(dia, UserTimeZoneService.PADRAO));
    }

    @Test
    @DisplayName("carimbo do PDF leva o fuso escrito — o arquivo sai da tela que sabia converter")
    void carimboMostraFuso() {
        assertTrue(UserTimeZoneService.carimbo(ZoneId.of("UTC")).endsWith(" UTC"));
        assertFalse(UserTimeZoneService.carimbo(ZoneId.of("Asia/Tokyo")).isBlank());
    }
}
