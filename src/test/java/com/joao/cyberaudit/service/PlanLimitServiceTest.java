package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.AccountType;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.Plan;
import com.joao.cyberaudit.model.Role;
import com.joao.cyberaudit.repository.DomainRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

/**
 * Plano efetivo por usuário.
 *
 * O que falhou em produção: {@code /auth/register} é público e entrega
 * {@code Role.OWNER} a todo mundo, então promover plano por role dava ENTERPRISE
 * a qualquer cadastro — scans ilimitados, Changes, gráfico de histórico e o scan
 * detalhado, tudo em conta FREE. Só o active scan escapou, porque ele já olhava
 * a lista de staff em vez do role.
 */
class PlanLimitServiceTest {

    private static final String STAFF   = "equipe@cyberaudit.com";
    private static final String CLIENTE = "cliente@example.com";

    private PlanLimitService service(String staffEmails) {
        return new PlanLimitService(
                mock(DomainRepository.class),
                new PlatformStaffService(staffEmails));
    }

    private AppUser usuario(String email, Role role, Plan plano, AccountType tipo) {
        Account account = Account.builder()
                .id(UUID.randomUUID())
                .type(tipo)
                .plan(plano)
                .build();

        return AppUser.builder()
                .id(UUID.randomUUID())
                .email(email)
                .role(role)
                .account(account)
                .build();
    }

    private AppUser cadastroComum(Plan plano) {
        // Exatamente o que /auth/register produz: OWNER da própria conta.
        return usuario(CLIENTE, Role.OWNER, plano, AccountType.INDIVIDUAL);
    }

    // ── A regressão ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("cadastro comum é OWNER, mas continua FREE — role não promove plano")
    void ownerDeCadastroNaoViraEnterprise() {
        var service = service("");

        assertEquals(Plan.FREE, service.effectivePlan(cadastroComum(Plan.FREE)));
    }

    @Test
    @DisplayName("ADMIN de conta também não promove plano")
    void adminNaoViraEnterprise() {
        var service = service("");

        assertEquals(Plan.FREE, service.effectivePlan(
                usuario(CLIENTE, Role.ADMIN, Plan.FREE, AccountType.COMPANY)));
    }

    @Test
    @DisplayName("FREE logado não vê impacto/correção/breakdown")
    void freeNaoTemDetalhe() {
        var entitlement = new ScanEntitlementService(service(""));

        assertFalse(entitlement.hasDetailAccess(cadastroComum(Plan.FREE)));
    }

    @Test
    @DisplayName("FREE logado não tem Changes nem gráfico de histórico, e tem limite diário")
    void freeMantemLimitesDoTier() {
        var service = service("");
        Plan plano  = service.effectivePlan(cadastroComum(Plan.FREE));

        assertFalse(plano.changesModuleAllowed, "Changes é PRO+");
        assertFalse(plano.historyChartAllowed,  "gráfico de histórico é PRO+");
        assertFalse(plano.activeScanAllowed,    "active scan é ENTERPRISE");
        assertTrue(plano.pdfExportAllowed,      "PDF é liberado para quem loga");
        assertEquals(10, plano.dailyScanLimit,  "FREE tem limite diário, não ilimitado");
    }

    // ── Agendamentos e domínio próprio ───────────────────────────────────────

    @Test
    @DisplayName("FREE não tem agendamento nem cadastro de domínio; PRO tem os dois")
    void agendamentoEDominioSaoProEmDiante() {
        var service = service("");

        Plan free = service.effectivePlan(cadastroComum(Plan.FREE));
        assertEquals(0, free.scheduledScanLimit, "FREE não agenda");
        assertFalse(free.domainRegistrationAllowed, "FREE não cadastra domínio");

        Plan pro = service.effectivePlan(cadastroComum(Plan.PRO));
        assertEquals(10, pro.scheduledScanLimit);
        assertTrue(pro.domainRegistrationAllowed);
    }

    @Test
    @DisplayName("cadastro de domínio no FREE responde 402, e passa no PRO")
    void checkDomainRegistration() {
        var service = service("");

        var erro = assertThrows(ResponseStatusException.class,
                () -> service.checkDomainRegistration(cadastroComum(Plan.FREE)));
        assertEquals(HttpStatus.PAYMENT_REQUIRED, erro.getStatusCode());

        assertDoesNotThrow(() -> service.checkDomainRegistration(cadastroComum(Plan.PRO)));
        assertDoesNotThrow(() -> service.checkDomainRegistration(cadastroComum(Plan.ENTERPRISE)));
    }

    @Test
    @DisplayName("relatórios da conta (auditoria, PDF executivo, status) são PRO+")
    void relatoriosSaoProEmDiante() {
        var service = service("");

        var erro = assertThrows(ResponseStatusException.class,
                () -> service.checkReportsModule(cadastroComum(Plan.FREE)));
        assertEquals(HttpStatus.PAYMENT_REQUIRED, erro.getStatusCode());

        assertDoesNotThrow(() -> service.checkReportsModule(cadastroComum(Plan.PRO)));
        assertDoesNotThrow(() -> service.checkReportsModule(cadastroComum(Plan.ENTERPRISE)));
    }

    @Test
    @DisplayName("gestão de equipe NÃO é gateada por plano — COMPANY FREE monta o time")
    void gestaoDeEquipeNaoDependeDePlano() {
        // Nenhum check de plano cobre usuários/convites/2FA: é decisão de produto,
        // não descuido. Se alguém gatear isso um dia, este teste cai junto com a
        // razão escrita aqui.
        var free = service("").effectivePlan(
                usuario(CLIENTE, Role.OWNER, Plan.FREE, AccountType.COMPANY));

        assertEquals(Plan.FREE, free);
        assertFalse(free.reportsModuleAllowed, "relatórios seguem PRO+");
    }

    @Test
    @DisplayName("primeiro agendamento no FREE já estoura o limite")
    void agendamentoBloqueadoNoFree() {
        var service = service("");

        var erro = assertThrows(ResponseStatusException.class,
                () -> service.checkScheduledScanSlots(cadastroComum(Plan.FREE), 0));
        assertEquals(HttpStatus.PAYMENT_REQUIRED, erro.getStatusCode());
    }

    // ── Quem realmente deve ser promovido ────────────────────────────────────

    @Test
    @DisplayName("equipe da plataforma recebe ENTERPRISE mesmo com conta FREE")
    void staffViraEnterprise() {
        var service = service(STAFF);

        assertEquals(Plan.ENTERPRISE, service.effectivePlan(
                usuario(STAFF, Role.OWNER, Plan.FREE, AccountType.INDIVIDUAL)));
    }

    @Test
    @DisplayName("isPlatformStaff distingue equipe de dono da própria conta")
    void isPlatformStaffNaoOlhaRole() {
        var service = service(STAFF);

        assertTrue(service.isPlatformStaff(
                usuario(STAFF, Role.OWNER, Plan.FREE, AccountType.INDIVIDUAL)));
        // OWNER é o que /auth/register dá a todo mundo — não pode virar staff.
        assertFalse(service.isPlatformStaff(
                usuario(CLIENTE, Role.OWNER, Plan.ENTERPRISE, AccountType.COMPANY)));
    }

    @Test
    @DisplayName("lista de staff vazia (padrão) não promove ninguém")
    void semStaffConfiguradoNinguemSobe() {
        var service = service("");

        assertEquals(Plan.FREE, service.effectivePlan(
                usuario(STAFF, Role.OWNER, Plan.FREE, AccountType.INDIVIDUAL)));
    }

    // ── O plano da conta continua valendo ────────────────────────────────────

    @Test
    @DisplayName("PRO e ENTERPRISE seguem vindo da conta, não do role")
    void planoDaContaPrevalece() {
        var service = service("");

        assertEquals(Plan.PRO, service.effectivePlan(cadastroComum(Plan.PRO)));
        assertEquals(Plan.ENTERPRISE, service.effectivePlan(cadastroComum(Plan.ENTERPRISE)));
        assertTrue(new ScanEntitlementService(service).hasDetailAccess(cadastroComum(Plan.PRO)));
    }

    @Test
    @DisplayName("guest (usuário nulo) é FREE e sem detalhe")
    void guestEFree() {
        var service = service("");

        assertEquals(Plan.FREE, service.effectivePlan((AppUser) null));
        assertFalse(new ScanEntitlementService(service).hasDetailAccess(null));
    }
}
