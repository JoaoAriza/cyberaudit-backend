package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.AccountType;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.Plan;
import com.joao.cyberaudit.model.RiskLevel;
import com.joao.cyberaudit.model.Role;
import com.joao.cyberaudit.model.ScanResult;
import com.joao.cyberaudit.model.ScoreResult;
import com.joao.cyberaudit.model.SecurityIssue;
import com.joao.cyberaudit.repository.DomainRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

/**
 * Gating de detalhe do scan por plano.
 *
 * O título é o "o quê" do problema — é ele que o guest/FREE não pode ler nos
 * achados que importam. LOW continua visível de propósito: serve de amostra do
 * relatório sem entregar nada aproveitável.
 */
class ScanEntitlementServiceTest {

    private ScanEntitlementService service() {
        return new ScanEntitlementService(
                new PlanLimitService(mock(DomainRepository.class), new PlatformStaffService("")));
    }

    private AppUser usuario(Plan plano) {
        return AppUser.builder()
                .id(UUID.randomUUID())
                .email("cliente@example.com")
                .role(Role.OWNER)   // como /auth/register cria
                .account(Account.builder()
                        .id(UUID.randomUUID())
                        .type(AccountType.INDIVIDUAL)
                        .plan(plano)
                        .build())
                .build();
    }

    private ScanResult resultado() {
        List<SecurityIssue> issues = List.of(
                new SecurityIssue("A", "Risco de email spoofing", "CRITICAL", "impacto", "correcao"),
                new SecurityIssue("B", "Header ausente",          "HIGH",     "impacto", "correcao"),
                new SecurityIssue("C", "Cookie sem SameSite",     "MEDIUM",   "impacto", "correcao"),
                new SecurityIssue("D", "security.txt ausente",    "LOW",      "impacto", "correcao"));

        return ScanResult.builder()
                .url("https://example.com")
                .score(new ScoreResult(70, RiskLevel.MEDIUM, List.of("nota do breakdown"), issues))
                .build();
    }

    private SecurityIssue issue(ScanResult r, String id) {
        return r.getScore().getIssues().stream()
                .filter(i -> i.getId().equals(id))
                .findFirst()
                .orElseThrow();
    }

    // ── FREE ─────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("CRITICAL tem o título oculto para FREE, igual a HIGH e MEDIUM")
    void criticalEOcultoParaFree() {
        ScanResult r = service().applyEntitlement(resultado(), usuario(Plan.FREE));

        assertNull(issue(r, "A").getTitle(), "CRITICAL não pode entregar o título");
        assertNull(issue(r, "B").getTitle(), "HIGH não pode entregar o título");
        assertNull(issue(r, "C").getTitle(), "MEDIUM não pode entregar o título");
    }

    @Test
    @DisplayName("LOW segue visível — é a amostra do relatório")
    void lowContinuaVisivelParaFree() {
        ScanResult r = service().applyEntitlement(resultado(), usuario(Plan.FREE));

        assertEquals("security.txt ausente", issue(r, "D").getTitle());
    }

    @Test
    @DisplayName("severidade é mantida em todos — alimenta a distribuição do gráfico")
    void severidadeSempreVisivel() {
        ScanResult r = service().applyEntitlement(resultado(), usuario(Plan.FREE));

        assertEquals("CRITICAL", issue(r, "A").getSeverity());
        assertEquals("LOW",      issue(r, "D").getSeverity());
    }

    @Test
    @DisplayName("impacto, correção e notas do breakdown somem para FREE")
    void detalheRemovidoParaFree() {
        ScanResult r = service().applyEntitlement(resultado(), usuario(Plan.FREE));

        assertNull(issue(r, "A").getImpact());
        assertNull(issue(r, "A").getRecommendation());
        assertNull(r.getScore().getNotes());
        assertTrue(r.isDetailsLocked());
    }

    @Test
    @DisplayName("o resultado original nunca é mutado — o cache é compartilhado")
    void naoMutaOOriginal() {
        ScanResult original = resultado();
        service().applyEntitlement(original, usuario(Plan.FREE));

        assertEquals("Risco de email spoofing", issue(original, "A").getTitle());
        assertNotNull(original.getScore().getNotes());
    }

    // ── PRO ──────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("PRO recebe o resultado inteiro, sem cópia")
    void proVeTudo() {
        ScanResult original = resultado();
        ScanResult r = service().applyEntitlement(original, usuario(Plan.PRO));

        assertSame(original, r);
        assertEquals("Risco de email spoofing", issue(r, "A").getTitle());
    }
}
