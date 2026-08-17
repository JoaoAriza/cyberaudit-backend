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

    // ── Quem realmente deve ser promovido ────────────────────────────────────

    @Test
    @DisplayName("equipe da plataforma recebe ENTERPRISE mesmo com conta FREE")
    void staffViraEnterprise() {
        var service = service(STAFF);

        assertEquals(Plan.ENTERPRISE, service.effectivePlan(
                usuario(STAFF, Role.OWNER, Plan.FREE, AccountType.INDIVIDUAL)));
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
