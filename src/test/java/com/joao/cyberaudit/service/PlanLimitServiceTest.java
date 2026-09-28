package com.joao.cyberaudit.service;

import com.joao.cyberaudit.exception.DomainOwnershipRequiredException;
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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

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
    @DisplayName("FREE logado só tem os 10 scans do dia — nem módulo, nem entrega de laudo")
    void freeMantemLimitesDoTier() {
        var service = service("");
        Plan plano  = service.effectivePlan(cadastroComum(Plan.FREE));

        assertFalse(plano.changesModuleAllowed, "Changes é PRO+");
        assertFalse(plano.historyChartAllowed,  "gráfico de histórico é PRO+");
        assertFalse(plano.activeScanAllowed,    "active scan é ENTERPRISE");
        assertFalse(plano.pdfExportAllowed,     "PDF virou recurso pago");
        assertFalse(plano.emailNotifyAllowed,   "notificação por e-mail virou recurso pago");
        assertEquals(10, plano.dailyScanLimit,  "FREE tem limite diário, não ilimitado");
    }

    // ── Contador diário de scans ──────────────────────────────────────────────

    /**
     * O que motivou este teste: em produção o badge da UI (remainingScans/dailyLimit)
     * não se move depois de um scan — ele só é buscado no login/boot, e nada chama
     * refreshUser() quando um scan termina. Isso deixou dúvida se o bloqueio em si
     * funciona, ou se o contador do backend também está travado. Aqui não tem tela:
     * chama checkAndIncrementDailyScan direto, a mesma chamada que ScanController
     * faz por trás de cada /scan e /scan/async.
     */
    @Test
    @DisplayName("FREE consome a cota a cada scan e é bloqueado exatamente no 11o do dia")
    void freeBloqueiaAposODecimoScanDoDia() {
        var service = service("");
        var free    = cadastroComum(Plan.FREE);

        for (int i = 1; i <= 10; i++) {
            final int n = i;
            assertDoesNotThrow(() -> service.checkAndIncrementDailyScan(free),
                    "scan " + n + " deveria passar (dentro do limite de 10)");
            assertEquals(10 - i, service.getRemainingScans(free),
                    "restantes deveria refletir o uso apos o scan " + n);
        }

        var erro = assertThrows(ResponseStatusException.class,
                () -> service.checkAndIncrementDailyScan(free),
                "o 11o scan do dia deveria ser bloqueado");
        assertEquals(HttpStatus.PAYMENT_REQUIRED, erro.getStatusCode());

        // A tentativa bloqueada não pode ter consumido cota: senão o contador
        // vazaria abaixo de zero a cada nova tentativa depois do limite.
        assertEquals(0, service.getRemainingScans(free));
    }

    @Test
    @DisplayName("o contador diário é por conta: duas contas FREE não compartilham cota")
    void contadorDiarioEPorConta() {
        var service = service("");
        var contaA  = cadastroComum(Plan.FREE);
        var contaB  = usuario("outra@example.com", Role.OWNER, Plan.FREE, AccountType.INDIVIDUAL);

        for (int i = 0; i < 10; i++) service.checkAndIncrementDailyScan(contaA);

        assertEquals(0, service.getRemainingScans(contaA));
        assertEquals(10, service.getRemainingScans(contaB),
                "conta B não deveria ter sido afetada pelo consumo da conta A");
        assertDoesNotThrow(() -> service.checkAndIncrementDailyScan(contaB));
    }

    // ── Scan ativo em domínio de terceiro ─────────────────────────────────────

    /**
     * checkActiveScan nunca tinha teste direto — só checkPdfExport/checkEmailNotify,
     * que passam pela mesma verificação de domínio mas não são o mesmo método. Esta
     * é a checagem que decide se o botão ACTIVE efetivamente dispara port scan e
     * probes de injeção contra um host, então merece cobertura própria.
     */
    @Test
    @DisplayName("PRO tenta scan ativo em domínio de terceiro — DomainOwnershipRequiredException, mesmo pagando")
    void proBloqueiaScanAtivoEmDominioNaoVerificado() {
        var service = serviceComVerificados("meu-dominio.com");
        var pro     = cadastroComum(Plan.PRO);

        var erro = assertThrows(DomainOwnershipRequiredException.class,
                () -> service.checkActiveScan(pro, "site-de-terceiro.com"));
        assertEquals("site-de-terceiro.com", erro.getHost());
        assertTrue(erro.getMessage().contains("domínios verificados"),
                "mensagem deveria orientar a verificar o domínio, não só recusar");
    }

    @Test
    @DisplayName("ENTERPRISE também precisa verificar o domínio — plano mais caro não pula a prova de posse")
    void enterpriseNaoPulaVerificacaoDeDominio() {
        var service    = serviceComVerificados();   // nenhum domínio verificado
        var enterprise = usuario(CLIENTE, Role.OWNER, Plan.ENTERPRISE, AccountType.COMPANY);

        assertThrows(DomainOwnershipRequiredException.class,
                () -> service.checkActiveScan(enterprise, "site-de-terceiro.com"));
    }

    @Test
    @DisplayName("PRO com o domínio verificado (exato ou subdomínio) passa no scan ativo")
    void proLiberaScanAtivoNoProprioDominioEDominioFilho() {
        var service = serviceComVerificados("meu-dominio.com");
        var pro     = cadastroComum(Plan.PRO);

        assertDoesNotThrow(() -> service.checkActiveScan(pro, "https://meu-dominio.com/rota"));
        assertDoesNotThrow(() -> service.checkActiveScan(pro, "api.meu-dominio.com"));
    }

    @Test
    @DisplayName("FREE pessoal nem chega a checar domínio — 402 direto por causa do plano")
    void freeIndividualBloqueiaScanAtivoAntesDoDominio() {
        var service = serviceComVerificados("qualquer-dominio.com");
        var free    = cadastroComum(Plan.FREE);

        var erro = assertThrows(ResponseStatusException.class,
                () -> service.checkActiveScan(free, "qualquer-dominio.com"));
        assertEquals(HttpStatus.PAYMENT_REQUIRED, erro.getStatusCode(),
                "FREE individual é barrado pelo plano (402), nem chega no check de domínio (403)");
    }

    @Test
    @DisplayName("equipe da plataforma dispensa a prova de posse")
    void staffDispensaVerificacaoDeDominio() {
        var staff = usuario(STAFF, Role.OWNER, Plan.FREE, AccountType.INDIVIDUAL);

        assertDoesNotThrow(() -> service(STAFF).checkActiveScan(staff, "qualquer-site.com"));
    }

    // ── Entrega de laudo: PDF e e-mail ───────────────────────────────────────

    /**
     * O que falhou em produção: o gating de detalhe vivia só no caminho da tela.
     * O e-mail do scan mandava o resultado cru, então uma conta FREE recebia na
     * caixa de entrada os títulos MEDIUM/HIGH que a tela mostrava borrados. A
     * política que saiu dali: entrega de laudo é paga, e no Pro pessoal só vale
     * sobre domínio que a conta provou possuir.
     */
    private PlanLimitService serviceComVerificados(String... hosts) {
        DomainRepository repo = mock(DomainRepository.class);
        for (String host : hosts) {
            when(repo.existsByAccountAndHostAndVerifiedTrue(any(), eq(host))).thenReturn(true);
        }
        return new PlanLimitService(repo, new PlatformStaffService(""));
    }

    @Test
    @DisplayName("FREE não exporta PDF nem recebe e-mail — 402 nos dois")
    void freeNaoRecebeLaudo() {
        var service = service("");
        var free    = cadastroComum(Plan.FREE);

        assertEquals(HttpStatus.PAYMENT_REQUIRED, assertThrows(ResponseStatusException.class,
                () -> service.checkPdfExport(free, "exemplo.com")).getStatusCode());
        assertEquals(HttpStatus.PAYMENT_REQUIRED, assertThrows(ResponseStatusException.class,
                () -> service.checkEmailNotify(free, "exemplo.com")).getStatusCode());
    }

    @Test
    @DisplayName("Pro pessoal entrega laudo do domínio verificado, e do subdomínio dele")
    void proPessoalEntregaNoProprioDominio() {
        var service = serviceComVerificados("empresa.com.br");
        var pro     = cadastroComum(Plan.PRO);

        assertDoesNotThrow(() -> service.checkPdfExport(pro, "https://empresa.com.br/rota"));
        assertDoesNotThrow(() -> service.checkEmailNotify(pro, "empresa.com.br"));
        // parentDomain: o verificado é o pai, o alvo é o subdomínio
        assertDoesNotThrow(() -> service.checkPdfExport(pro, "api.empresa.com.br"));
    }

    @Test
    @DisplayName("Pro pessoal não gera laudo de site de terceiro — 403")
    void proPessoalNaoEntregaDeTerceiro() {
        var service = serviceComVerificados("empresa.com.br");
        var pro     = cadastroComum(Plan.PRO);

        assertEquals(HttpStatus.FORBIDDEN, assertThrows(ResponseStatusException.class,
                () -> service.checkPdfExport(pro, "site-do-cliente.com")).getStatusCode());
        assertEquals(HttpStatus.FORBIDDEN, assertThrows(ResponseStatusException.class,
                () -> service.checkEmailNotify(pro, "site-do-cliente.com")).getStatusCode());
    }

    @Test
    @DisplayName("conta Empresa e ENTERPRISE entregam laudo de qualquer domínio")
    void empresaNaoTemRestricaoDeDominio() {
        var service = serviceComVerificados();   // nenhum domínio verificado

        var proEmpresa = usuario(CLIENTE, Role.OWNER, Plan.PRO,        AccountType.COMPANY);
        var enterprise = usuario(CLIENTE, Role.OWNER, Plan.ENTERPRISE, AccountType.INDIVIDUAL);

        assertDoesNotThrow(() -> service.checkPdfExport(proEmpresa,   "site-qualquer.com"));
        assertDoesNotThrow(() -> service.checkEmailNotify(proEmpresa, "site-qualquer.com"));
        assertDoesNotThrow(() -> service.checkPdfExport(enterprise,   "site-qualquer.com"));
        assertDoesNotThrow(() -> service.checkEmailNotify(enterprise, "site-qualquer.com"));
    }

    @Test
    @DisplayName("canEmailNotify devolve false em vez de lançar — o agendador não pode quebrar")
    void agendadorNaoQuebraQuandoOPlanoCai() {
        var service = serviceComVerificados();

        assertFalse(service.canEmailNotify(cadastroComum(Plan.FREE), "exemplo.com"));
        assertFalse(service.canEmailNotify(cadastroComum(Plan.PRO),  "site-de-terceiro.com"));
        assertTrue(serviceComVerificados("meu.com")
                .canEmailNotify(cadastroComum(Plan.PRO), "meu.com"));
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
