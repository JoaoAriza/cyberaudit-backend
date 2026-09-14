package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.AccountType;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.FormSurfaceResult;
import com.joao.cyberaudit.model.ImpactLevel;
import com.joao.cyberaudit.model.ImpactSignal;
import com.joao.cyberaudit.model.ImpactSource;
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
                .lang("pt")
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
    @DisplayName("o carimbo de idioma sobrevive ao gating — a cópia é por toBuilder, não campo a campo")
    void carimboDeIdiomaSobreviveAoGating() {
        // A cópia do gating é `toBuilder()`, que copia tudo. Se algum dia virar
        // construção campo a campo, o `lang` cai fora em silêncio — e a tela para de
        // avisar que o laudo está em outro idioma, sem nada quebrar.
        ScanResult r = service().applyEntitlement(resultado(), usuario(Plan.FREE));

        assertEquals("pt", r.getLang());
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

    // ── Rótulo de impacto ────────────────────────────────────────────────────

    private ScanResult resultadoComImpacto() {
        return resultado().toBuilder()
                .impact(ImpactLevel.PAYMENT)
                .impactSignals(List.of(
                        new ImpactSignal(ImpactSource.FORM, "payment-field"),
                        new ImpactSignal(ImpactSource.COOKIES, "PHPSESSID")))
                .impactIndicators(List.of(new ImpactSignal(ImpactSource.JWT, "access_token")))
                .formSurface(FormSurfaceResult.builder()
                        .hasForm(true).hasPaymentField(true)
                        .evidence(List.of("form", "payment-field")).build())
                .managedPlatform("Nuvemshop")
                .build();
    }

    @Test
    @DisplayName("FREE vê o nível e EM QUAL módulo a página é sensível, mas não o porquê")
    void freeVeOrigemSemDetalhe() {
        ScanResult r = service().applyEntitlement(resultadoComImpacto(), usuario(Plan.FREE));

        assertEquals(ImpactLevel.PAYMENT, r.getImpact());
        assertEquals(List.of(ImpactSource.FORM, ImpactSource.COOKIES),
                r.getImpactSignals().stream().map(ImpactSignal::getSource).toList());
        assertTrue(r.getImpactSignals().stream().allMatch(s -> s.getDetail() == null),
                "o detalhe do sinal é o porquê — não pode chegar ao FREE");
        assertNull(r.getFormSurface(), "os booleanos do formulário entregam o mesmo porquê");
        assertEquals("Nuvemshop", r.getManagedPlatform());
    }

    @Test
    @DisplayName("indícios do domínio chegam ao FREE só com a origem, igual aos sinais")
    void freeVeIndicioSemDetalhe() {
        ScanResult r = service().applyEntitlement(resultadoComImpacto(), usuario(Plan.FREE));

        assertEquals(List.of(ImpactSource.JWT),
                r.getImpactIndicators().stream().map(ImpactSignal::getSource).toList());
        assertNull(r.getImpactIndicators().get(0).getDetail(), "qual token é o porquê");
    }

    @Test
    @DisplayName("tirar o detalhe do FREE não apaga o detalhe do cache compartilhado")
    void detalheDoCacheIntacto() {
        ScanResult original = resultadoComImpacto();
        service().applyEntitlement(original, usuario(Plan.FREE));

        assertEquals("payment-field", original.getImpactSignals().get(0).getDetail());
        assertEquals("access_token", original.getImpactIndicators().get(0).getDetail());
        assertNotNull(original.getFormSurface());
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
