package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.AccountType;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.Plan;
import com.joao.cyberaudit.model.Role;
import com.joao.cyberaudit.repository.DomainRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

/**
 * Requisições por minuto por plano (BUG-20, cyberaudit-qa).
 *
 * Antes o limite vinha do papel: OWNER sem limite, FREE_EMPLOYEE 60, ADMIN 120. Como todo
 * cadastro sai OWNER, só o visitante era limitado de fato.
 *
 * Os laços aqui gastam o balde em microssegundos. O balde repõe 1 ficha a cada
 * 60/limite segundos (0,5 s no ENTERPRISE), então a conta "o limite + 1 recusa" é exata.
 */
class RateLimitServiceTest {

    private static final String STAFF = "equipe@cyberaudit.test";
    private static final String IP    = "203.0.113.10";

    private final RateLimitService service = new RateLimitService(new PlanLimitService(
            mock(DomainRepository.class), new PlatformStaffService(STAFF)));

    private static AppUser usuario(String email, Role papel, Plan plano, AccountType tipo) {
        Account conta = Account.builder().id(UUID.randomUUID()).type(tipo).plan(plano).build();
        return AppUser.builder().id(UUID.randomUUID()).email(email).role(papel).account(conta).build();
    }

    /** Dono de conta pessoal, como sai do cadastro. */
    private static AppUser dono(Plan plano) {
        return usuario("cliente-" + UUID.randomUUID() + "@example.com",
                Role.OWNER, plano, AccountType.INDIVIDUAL);
    }

    private static AppUser membro(Plan plano, Role papel) {
        return usuario("membro-" + UUID.randomUUID() + "@example.com",
                papel, plano, AccountType.COMPANY);
    }

    /** Quantas chamadas seguidas passam antes da primeira recusa (para em {@code teto}). */
    private int passamAntesDeRecusar(AppUser user, int teto) {
        for (int i = 0; i < teto; i++) {
            if (!service.allow(IP, user)) return i;
        }
        return teto;
    }

    // ── Limite pelo plano, não pelo papel ───────────────────────────────────

    @Test
    @DisplayName("dono de conta FREE: 5 por minuto, a 6ª é recusada")
    void donoFree() {
        assertEquals(RateLimitService.FREE_RPM, passamAntesDeRecusar(dono(Plan.FREE), 50));
    }

    @Test
    @DisplayName("dono de conta PRO: 60 por minuto, a 61ª é recusada")
    void donoPro() {
        assertEquals(RateLimitService.PRO_RPM, passamAntesDeRecusar(dono(Plan.PRO), 500));
    }

    @Test
    @DisplayName("dono de conta ENTERPRISE fora da equipe da plataforma: 120 por minuto")
    void donoEnterprise() {
        assertEquals(RateLimitService.ENTERPRISE_RPM,
                passamAntesDeRecusar(dono(Plan.ENTERPRISE), 500));
    }

    @Test
    @DisplayName("membro (FREE_EMPLOYEE) de conta FREE: 5, o plano da conta, e não 60")
    void membroDeContaFree() {
        assertEquals(RateLimitService.FREE_RPM,
                passamAntesDeRecusar(membro(Plan.FREE, Role.FREE_EMPLOYEE), 500));
    }

    @Test
    @DisplayName("membro (FREE_EMPLOYEE) de conta ENTERPRISE: 120, e não 60")
    void membroDeContaEnterprise() {
        assertEquals(RateLimitService.ENTERPRISE_RPM,
                passamAntesDeRecusar(membro(Plan.ENTERPRISE, Role.FREE_EMPLOYEE), 500));
    }

    @Test
    @DisplayName("ADMIN de conta PRO: 60, o plano da conta, e não 120")
    void adminDeContaPro() {
        assertEquals(RateLimitService.PRO_RPM,
                passamAntesDeRecusar(membro(Plan.PRO, Role.ADMIN), 500));
    }

    @Test
    @DisplayName("conta sem plano gravado conta como FREE")
    void contaSemPlano() {
        assertEquals(RateLimitService.FREE_RPM, passamAntesDeRecusar(dono(null), 50));
    }

    // ── Troca de plano ──────────────────────────────────────────────────────

    @Test
    @DisplayName("FREE que esgotou o minuto e assina o PRO passa a usar o balde do PRO na hora")
    void upgradeTrocaDeBalde() {
        AppUser user = dono(Plan.FREE);
        assertEquals(RateLimitService.FREE_RPM, passamAntesDeRecusar(user, 50));

        user.getAccount().setPlan(Plan.PRO);
        assertEquals(RateLimitService.PRO_RPM, passamAntesDeRecusar(user, 500));
    }

    @Test
    @DisplayName("PRO que volta para o FREE cai para 5 por minuto")
    void downgradeTrocaDeBalde() {
        AppUser user = dono(Plan.PRO);
        assertTrue(service.allow(IP, user));

        user.getAccount().setPlan(Plan.FREE);
        assertEquals(RateLimitService.FREE_RPM, passamAntesDeRecusar(user, 500));
    }

    // ── Isenção e controles ─────────────────────────────────────────────────

    @Test
    @DisplayName("equipe da plataforma fica isenta, mesmo numa conta FREE")
    void equipeIsenta() {
        AppUser staff = usuario(STAFF, Role.OWNER, Plan.FREE, AccountType.INDIVIDUAL);
        assertEquals(500, passamAntesDeRecusar(staff, 500));
    }

    @Test
    @DisplayName("controle: visitante continua com 5 por minuto, por IP")
    void visitantePorIp() {
        for (int i = 0; i < RateLimitService.GUEST_RPM; i++) {
            assertTrue(service.allow(IP, null), "chamada " + (i + 1));
        }
        assertFalse(service.allow(IP, null));
        assertTrue(service.allow("203.0.113.11", null), "outro IP tem balde próprio");
    }

    @Test
    @DisplayName("controle: usuários diferentes têm baldes diferentes, mesmo no mesmo IP")
    void baldePorUsuario() {
        AppUser a = dono(Plan.FREE);
        assertEquals(RateLimitService.FREE_RPM, passamAntesDeRecusar(a, 50));
        assertTrue(service.allow(IP, dono(Plan.FREE)));
        assertTrue(service.allow(IP, null), "o visitante do mesmo IP também não é afetado");
    }

    @Test
    @DisplayName("controle: o limite genérico (billing) não mudou")
    void limiteGenerico() {
        for (int i = 0; i < 3; i++) assertTrue(service.allow("checkout:x", 3, 60_000));
        assertFalse(service.allow("checkout:x", 3, 60_000));
    }
}
