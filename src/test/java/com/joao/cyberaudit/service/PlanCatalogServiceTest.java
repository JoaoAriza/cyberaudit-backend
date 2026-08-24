package com.joao.cyberaudit.service;

import com.joao.cyberaudit.dto.PlanCatalogDto;
import com.joao.cyberaudit.dto.PlanCatalogDto.Feature;
import com.joao.cyberaudit.dto.PlanCatalogDto.State;
import com.joao.cyberaudit.model.Plan;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.math.BigDecimal;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * O cardápio vindo do enum.
 *
 * O que falhou: a matriz de recursos era mantida à mão no Frontend e envelheceu em
 * silêncio — quatro recursos criados no backend nunca chegaram à tela de planos,
 * e um deles era o principal diferencial pago. Os preços, idem: chumbados no
 * Frontend enquanto o backend já os lia de configuração.
 *
 * O teste que importa aqui é o {@link #todaTravaDePlanoApareceNoCardapio()}: ele
 * varre os campos de {@link Plan} por reflexão e falha quando alguém adiciona uma
 * trava nova sem colocá-la no catálogo. É a única forma de a lista não voltar a
 * mentir — as outras asserções só descrevem o estado de hoje.
 */
class PlanCatalogServiceTest {

    private static final BigDecimal PRECO_PRO        = new BigDecimal("29.90");
    private static final BigDecimal PRECO_ENTERPRISE = new BigDecimal("99.90");

    private PlanCatalogService service() {
        var s = new PlanCatalogService();
        ReflectionTestUtils.setField(s, "currency", "BRL");
        ReflectionTestUtils.setField(s, "proAmount", PRECO_PRO);
        ReflectionTestUtils.setField(s, "enterpriseAmount", PRECO_ENTERPRISE);
        return s;
    }

    private Map<String, Feature> recursosDe(Plan plan) {
        PlanCatalogDto dto = service().catalogo().stream()
                .filter(p -> p.getPlan().equals(plan.name()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("plano ausente do catálogo: " + plan));
        return dto.getFeatures().stream()
                .collect(Collectors.toMap(Feature::getId, f -> f));
    }

    // ── A trava contra o envelhecimento ──────────────────────────────────────

    @Test
    @DisplayName("toda trava de plano do enum aparece no cardápio")
    void todaTravaDePlanoApareceNoCardapio() throws Exception {
        // Os booleanos públicos de Plan são, por definição, recursos que o plano
        // libera ou não. Se existe um que o cardápio não conta, o cliente paga sem
        // saber o que está comprando — foi exatamente o que aconteceu.
        Set<String> noCardapio = recursosDe(Plan.PRO).keySet();

        for (Field campo : Plan.class.getDeclaredFields()) {
            if (!Modifier.isPublic(campo.getModifiers())
                    || Modifier.isStatic(campo.getModifiers())
                    || campo.getType() != boolean.class) {
                continue;
            }
            assertTrue(mapeado(campo.getName(), noCardapio),
                    "Plan." + campo.getName() + " não tem linha no cardápio. "
                    + "Adicione a chave em PlanCatalogService (e o rótulo no Frontend) "
                    + "ou o recurso vira trava invisível para quem paga.");
        }
    }

    /**
     * Liga o nome do campo do enum à chave do catálogo. Explícito de propósito:
     * derivar por convenção de nome esconderia justamente o campo esquecido.
     */
    private boolean mapeado(String campoDoEnum, Set<String> chaves) {
        return switch (campoDoEnum) {
            case "activeScanAllowed"         -> chaves.contains(PlanCatalogService.ACTIVE_SCAN);
            case "pdfExportAllowed"          -> chaves.contains(PlanCatalogService.PDF_EXPORT);
            case "emailNotifyAllowed"        -> chaves.contains(PlanCatalogService.EMAIL_NOTIFY);
            case "changesModuleAllowed"      -> chaves.contains(PlanCatalogService.CHANGES_MODULE);
            case "historyChartAllowed"       -> chaves.contains(PlanCatalogService.HISTORY_CHART);
            case "domainRegistrationAllowed" -> chaves.contains(PlanCatalogService.DOMAIN_REGISTRATION);
            case "reportsModuleAllowed"      -> chaves.contains(PlanCatalogService.ACCOUNT_REPORTS);
            default -> false;
        };
    }

    // ── O estado de hoje ─────────────────────────────────────────────────────

    @Test
    @DisplayName("o catálogo traz os três planos, na ordem dos cards")
    void trazOsTresPlanos() {
        List<PlanCatalogDto> catalogo = service().catalogo();

        assertEquals(List.of("FREE", "PRO", "ENTERPRISE"),
                catalogo.stream().map(PlanCatalogDto::getPlan).toList());
    }

    @Test
    @DisplayName("preço vem da configuração; FREE não tem preço")
    void precoVemDaConfiguracao() {
        Map<String, PlanCatalogDto> porPlano = service().catalogo().stream()
                .collect(Collectors.toMap(PlanCatalogDto::getPlan, p -> p));

        assertNull(porPlano.get("FREE").getAmount(), "FREE não se assina");
        assertEquals(PRECO_PRO, porPlano.get("PRO").getAmount());
        assertEquals(PRECO_ENTERPRISE, porPlano.get("ENTERPRISE").getAmount());
        assertEquals("BRL", porPlano.get("PRO").getCurrency());
    }

    @Test
    @DisplayName("FREE não entrega laudo nem mostra o detalhe do achado")
    void freeNaoTemOsPagos() {
        var f = recursosDe(Plan.FREE);

        assertEquals(State.NO, f.get(PlanCatalogService.FINDING_DETAIL).getState());
        assertEquals(State.NO, f.get(PlanCatalogService.PDF_EXPORT).getState());
        assertEquals(State.NO, f.get(PlanCatalogService.EMAIL_NOTIFY).getState());
        assertEquals(State.NO, f.get(PlanCatalogService.ACTIVE_SCAN).getState());
        assertEquals(State.NO, f.get(PlanCatalogService.SCHEDULED_SCANS).getState());
        assertEquals(10, f.get(PlanCatalogService.DAILY_SCANS).getLimit());
    }

    @Test
    @DisplayName("Pessoal Pro entrega laudo, mas só no domínio verificado")
    void proEntregaSoNoProprioDominio() {
        var f = recursosDe(Plan.PRO);

        assertEquals(State.VERIFIED_DOMAINS_ONLY, f.get(PlanCatalogService.PDF_EXPORT).getState());
        assertEquals(State.VERIFIED_DOMAINS_ONLY, f.get(PlanCatalogService.EMAIL_NOTIFY).getState());
        assertEquals(State.VERIFIED_DOMAINS_ONLY, f.get(PlanCatalogService.ACTIVE_SCAN).getState());
        assertEquals(State.YES, f.get(PlanCatalogService.FINDING_DETAIL).getState());
        assertEquals(-1, f.get(PlanCatalogService.DAILY_SCANS).getLimit(), "-1 = ilimitado");
        assertEquals(10, f.get(PlanCatalogService.SCHEDULED_SCANS).getLimit());
    }

    @Test
    @DisplayName("Empresa não tem restrição de domínio em nada")
    void empresaNaoTemRestricaoDeDominio() {
        var f = recursosDe(Plan.ENTERPRISE);

        assertEquals(State.YES, f.get(PlanCatalogService.PDF_EXPORT).getState());
        assertEquals(State.YES, f.get(PlanCatalogService.EMAIL_NOTIFY).getState());
        assertEquals(State.YES, f.get(PlanCatalogService.ACTIVE_SCAN).getState());
        assertEquals(-1, f.get(PlanCatalogService.SCHEDULED_SCANS).getLimit());
    }
}
