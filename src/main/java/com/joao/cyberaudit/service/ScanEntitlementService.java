package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.Plan;
import com.joao.cyberaudit.model.ScanResult;
import com.joao.cyberaudit.model.ScoreResult;
import com.joao.cyberaudit.model.SecurityIssue;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Aplica o gating de detalhe por plano ao resultado de scan.
 *
 * Regra: apenas PRO / ENTERPRISE (e a equipe da plataforma, via
 * {@link PlanLimitService#effectivePlan}) veem impacto, correção e breakdown. Guest e FREE
 * recebem o resultado com esses campos removidos e {@code detailsLocked=true}.
 *
 * IMPORTANTE: nunca muta o resultado recebido — o {@code ScanOrchestrator} mantém um cache
 * compartilhado entre usuários, então a versão travada é sempre uma CÓPIA (via toBuilder).
 */
@Service
public class ScanEntitlementService {

    private final PlanLimitService planLimitService;

    public ScanEntitlementService(PlanLimitService planLimitService) {
        this.planLimitService = planLimitService;
    }

    /** true se o usuário pode ver impacto/correção/breakdown (PRO, ENTERPRISE ou staff). */
    public boolean hasDetailAccess(AppUser user) {
        Plan plan = planLimitService.effectivePlan(user); // null/guest → FREE
        return plan == Plan.PRO || plan == Plan.ENTERPRISE;
    }

    /**
     * Retorna o resultado adequado ao plano do requester. Para guest/FREE, devolve uma cópia
     * sem impacto/correção nas issues e sem as notas do score, com {@code detailsLocked=true}.
     * Para quem tem acesso, devolve o próprio resultado inalterado.
     */
    public ScanResult applyEntitlement(ScanResult result, AppUser user) {
        if (result == null || hasDetailAccess(user)) {
            return result;
        }

        ScoreResult strippedScore = result.getScore();
        if (strippedScore != null) {
            List<SecurityIssue> strippedIssues = strippedScore.getIssues() == null ? null :
                    strippedScore.getIssues().stream()
                            .map(i -> {
                                String sev = i.getSeverity() == null ? "" : i.getSeverity().toUpperCase();
                                // HIGH/MEDIUM: oculta também o título (o "o quê" do problema).
                                // CRITICAL/LOW: mantém o título (susto do crítico + trivial do low).
                                boolean hideTitle = sev.equals("HIGH") || sev.equals("MEDIUM");
                                return new SecurityIssue(
                                        i.getId(),
                                        hideTitle ? null : i.getTitle(),
                                        i.getSeverity(),   // severidade mantida (alimenta a distribuição)
                                        null,              // impacto oculto
                                        null);             // correção oculta
                            })
                            .toList();
            // notas do breakdown ocultas (podem conter recomendações). Distribuição fica liberada.
            strippedScore = new ScoreResult(
                    strippedScore.getScore(),
                    strippedScore.getRiskLevel(),
                    null,
                    strippedIssues);
        }

        // Zera as coleções detalhadas dos módulos GATED (evidências/riscos/soluções).
        // Módulos informativos de baixa sensibilidade permanecem VISÍVEIS para guest/FREE:
        //   - Transport Security → sslInfo, tlsDetails
        //   - Technology         → techFingerprint
        //   - Cert Transparency  → certTransparency
        // (mantidos em sincronia com FREE_MODULES no frontend). Metadados básicos
        // (url, status, score, moduleStatus) também permanecem.
        return result.toBuilder()
                .score(strippedScore)
                .detailsLocked(true)
                .headers(null)
                .openPorts(null)
                .wafDetectionResult(null)
                .corsResult(null)
                .cookieIssues(null)
                .sensitiveRobotsPaths(null)
                .sensitiveFiles(null)
                .dangerousHttpMethods(null)
                .dnsSecurityResult(null)
                .openRedirectFindings(null)
                .directoryListingFindings(null)
                .cveFindings(null)
                .changes(null)
                .subdomainTakeover(null)
                .apiDocsExposure(null)
                .graphQlIntrospection(null)
                .jwtSecurity(null)
                .pathTraversal(null)
                .ssrfFindings(null)
                .hostHeaderFindings(null)
                .sourceMapFindings(null)
                .crlfFindings(null)
                .relatedHostHeaders(null)
                .compliance(null)
                .build();
    }
}
