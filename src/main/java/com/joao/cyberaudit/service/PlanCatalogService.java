package com.joao.cyberaudit.service;

import com.joao.cyberaudit.dto.PlanCatalogDto;
import com.joao.cyberaudit.dto.PlanCatalogDto.Feature;
import com.joao.cyberaudit.dto.PlanCatalogDto.State;
import com.joao.cyberaudit.model.Plan;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

/**
 * Monta o cardápio de planos a partir do enum {@link Plan}.
 *
 * Existe porque o Frontend mantinha a mesma matriz à mão, e ela envelheceu: quatro
 * recursos criados no backend nunca chegaram à tela de planos, e os preços estavam
 * chumbados no código enquanto o backend já os lia de configuração — mudar o valor
 * no ambiente não refletia na tela que vende o produto.
 *
 * O catálogo descreve o PLANO, não uma conta. Onde a regra depende do tipo da
 * conta, cada entrada assume o formato em que o plano é vendido: PRO é o "Pessoal
 * Pro" (individual, preso a domínio verificado) e ENTERPRISE é o "Empresa", sem
 * restrição de domínio. É o que os três cards já significavam.
 *
 * Fora do catálogo de propósito: multi-usuário. Convite é liberado por
 * AccountType.COMPANY (InviteService), não por plano — não é diferença de plano e
 * vive como nota do card.
 */
@Service
public class PlanCatalogService {

    // Chaves estáveis. O Frontend traduz cada uma para rótulo; recurso novo com
    // trava de plano entra aqui e aparece na tela sem ninguém editar duas listas.
    public static final String FINDING_DETAIL      = "FINDING_DETAIL";
    public static final String DAILY_SCANS         = "DAILY_SCANS";
    public static final String PDF_EXPORT          = "PDF_EXPORT";
    public static final String EMAIL_NOTIFY        = "EMAIL_NOTIFY";
    public static final String CHANGES_MODULE      = "CHANGES_MODULE";
    public static final String HISTORY_CHART       = "HISTORY_CHART";
    public static final String SCHEDULED_SCANS     = "SCHEDULED_SCANS";
    public static final String DOMAIN_REGISTRATION = "DOMAIN_REGISTRATION";
    public static final String ACCOUNT_REPORTS     = "ACCOUNT_REPORTS";
    public static final String ACTIVE_SCAN         = "ACTIVE_SCAN";

    @Value("${billing.currency:BRL}")            private String     currency;
    @Value("${billing.pro.amount:29.90}")        private BigDecimal proAmount;
    @Value("${billing.enterprise.amount:99.90}") private BigDecimal enterpriseAmount;

    /** Os três planos, na ordem em que os cards aparecem. */
    public List<PlanCatalogDto> catalogo() {
        return List.of(montar(Plan.FREE), montar(Plan.PRO), montar(Plan.ENTERPRISE));
    }

    private PlanCatalogDto montar(Plan plan) {
        // Cada entrada assume o formato de venda do plano: PRO é o Pessoal Pro
        // (individual), ENTERPRISE é o Empresa.
        boolean contaEmpresa = plan == Plan.ENTERPRISE;
        boolean soVerificado = plan.verifiedDomainOnly(contaEmpresa);

        List<Feature> f = new ArrayList<>();

        // Espelha ScanEntitlementService.hasDetailAccess — o principal diferencial pago.
        f.add(liga(FINDING_DETAIL, plan == Plan.PRO || plan == Plan.ENTERPRISE));
        f.add(contavel(DAILY_SCANS, plan.dailyScanLimit));
        f.add(entrega(PDF_EXPORT,   plan.pdfExportAllowed,   soVerificado));
        f.add(entrega(EMAIL_NOTIFY, plan.emailNotifyAllowed, soVerificado));
        f.add(liga(CHANGES_MODULE,  plan.changesModuleAllowed));
        f.add(liga(HISTORY_CHART,   plan.historyChartAllowed));
        f.add(contavel(SCHEDULED_SCANS, plan.scheduledScanLimit));
        f.add(liga(DOMAIN_REGISTRATION, plan.domainRegistrationAllowed));
        f.add(liga(ACCOUNT_REPORTS,     plan.reportsModuleAllowed));
        // Mesma conta do AccountDto: o PRO faz scan ativo, só que no que é dele.
        f.add(entrega(ACTIVE_SCAN, plan.activeScanAllowed || plan == Plan.PRO, soVerificado));

        return PlanCatalogDto.builder()
                .plan(plan.name())
                .amount(preco(plan))
                .currency(currency)
                .features(f)
                .build();
    }

    private static Feature liga(String id, boolean permitido) {
        return Feature.builder().id(id).state(permitido ? State.YES : State.NO).build();
    }

    /** Recurso liberado pelo plano mas possivelmente limitado ao domínio próprio. */
    private static Feature entrega(String id, boolean permitido, boolean soVerificado) {
        State estado = !permitido ? State.NO
                     : soVerificado ? State.VERIFIED_DOMAINS_ONLY
                     : State.YES;
        return Feature.builder().id(id).state(estado).build();
    }

    /** Recurso de quantidade: -1 = ilimitado, 0 = não faz parte do plano. */
    private static Feature contavel(String id, int limite) {
        return Feature.builder()
                .id(id)
                .state(limite == 0 ? State.NO : State.YES)
                .limit(limite)
                .build();
    }

    /** null no FREE: não se assina, e preço zero na tela seria ruído. */
    private BigDecimal preco(Plan plan) {
        return switch (plan) {
            case PRO        -> proAmount;
            case ENTERPRISE -> enterpriseAmount;
            case FREE       -> null;
        };
    }
}
