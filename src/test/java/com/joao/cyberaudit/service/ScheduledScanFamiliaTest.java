package com.joao.cyberaudit.service;

import com.joao.cyberaudit.dto.ScheduledScanRequest;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.ScheduledScan;
import com.joao.cyberaudit.repository.ScheduledScanRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Agendamento por familia: o dominio e o caminho saem da URL digitada, e a mesma
 * pagina nao entra duas vezes na lista.
 */
class ScheduledScanFamiliaTest {

    private final ScheduledScanRepository repo = mock(ScheduledScanRepository.class);
    private final ScheduledScanService service = new ScheduledScanService(
            repo, mock(ScanOrchestrator.class), mock(EmailService.class),
            mock(PlanLimitService.class), mock(ScanEntitlementService.class),
            new UserTimeZoneService(mock(com.joao.cyberaudit.repository.AppUserRepository.class)));

    private final AppUser user = new AppUser();

    ScheduledScanFamiliaTest() {
        user.setId(UUID.randomUUID());
        when(repo.save(any(ScheduledScan.class))).thenAnswer(inv -> inv.getArgument(0));
    }

    private ScheduledScanRequest pedido(String url) {
        ScheduledScanRequest r = new ScheduledScanRequest();
        r.setHost(url);
        r.setFrequency("DAILY");
        r.setPreferredHour(9);
        return r;
    }

    private ScheduledScan existente(String host, String path) {
        return ScheduledScan.builder().host(host).path(path)
                .frequency(ScheduledScan.Frequency.DAILY).build();
    }

    @Test
    @DisplayName("o caminho sai da propria URL digitada, sem campo separado")
    void caminhoDaUrl() {
        when(repo.findByUserOrderByCreatedAtDesc(user)).thenReturn(List.of());

        service.create(pedido("https://www.linkedin.com/in/joaoariza/"), user);

        ArgumentCaptor<ScheduledScan> salvo = ArgumentCaptor.forClass(ScheduledScan.class);
        verify(repo).save(salvo.capture());
        assertEquals("www.linkedin.com", salvo.getValue().getHost());
        assertEquals("/in/joaoariza", salvo.getValue().getPath());
    }

    @Test
    @DisplayName("mesma pagina ja agendada e recusada, com ou sem www")
    void recusaDuplicado() {
        when(repo.findByUserOrderByCreatedAtDesc(user))
                .thenReturn(List.of(existente("www.linkedin.com", "/in/joaoariza")));

        ResponseStatusException e = assertThrows(ResponseStatusException.class,
                () -> service.create(pedido("linkedin.com/in/joaoariza"), user));
        assertEquals(HttpStatus.CONFLICT, e.getStatusCode());
        verify(repo, never()).save(any());
    }

    @Test
    @DisplayName("outra pagina da mesma familia entra normalmente")
    void outraPaginaDaFamilia() {
        when(repo.findByUserOrderByCreatedAtDesc(user))
                .thenReturn(List.of(existente("www.linkedin.com", "/in/joaoariza")));

        service.create(pedido("https://www.linkedin.com/"), user);

        verify(repo).save(any(ScheduledScan.class));
    }

    @Test
    @DisplayName("www e sem www sao a mesma familia; dominios diferentes nao")
    void familia() {
        assertTrue(ScheduledScanService.mesmaFamilia("www.linkedin.com", "linkedin.com"));
        assertTrue(ScheduledScanService.mesmaFamilia("LinkedIn.com", "linkedin.com"));
        assertFalse(ScheduledScanService.mesmaFamilia("linkedin.com", "linked.in"));
        assertFalse(ScheduledScanService.mesmaFamilia(null, "linkedin.com"));
    }
}
