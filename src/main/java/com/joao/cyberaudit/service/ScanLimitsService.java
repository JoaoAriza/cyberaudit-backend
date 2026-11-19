package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.AppUser;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

/**
 * Travas que TODO endpoint que dispara scan passa antes de chamar o orchestrator.
 *
 * Moravam como métodos privados do ScanController. O gate de CI
 * ({@code GET /api-keys/ci}) chamava o orchestrator direto e não tinha como usá-las:
 * rodava scan sem cota, sem rate limit e sem a trava de plano do ativo (BUG-19 do
 * cyberaudit-qa). Endpoint novo que dispara scan chama {@link #checkBeforeScan}.
 *
 * A prova de posse por arquivo ({@code /.well-known/cyberaudit.txt}) não está aqui:
 * ela mora dentro do orchestrator e vale para qualquer caminho.
 */
@Service
public class ScanLimitsService {

    private final RateLimitService      rateLimitService;
    private final GuestRateLimitService guestRateLimitService;
    private final PlanLimitService      planLimitService;
    private final ClientIpResolver      clientIpResolver;

    public ScanLimitsService(RateLimitService rateLimitService,
                             GuestRateLimitService guestRateLimitService,
                             PlanLimitService planLimitService,
                             ClientIpResolver clientIpResolver) {
        this.rateLimitService      = rateLimitService;
        this.guestRateLimitService = guestRateLimitService;
        this.planLimitService      = planLimitService;
        this.clientIpResolver      = clientIpResolver;
    }

    /**
     * Rate limit e depois os limites de custo. Nessa ordem: um 429 não gasta cota.
     */
    public void checkBeforeScan(String url, boolean active,
                                AppUser currentUser, HttpServletRequest request) {
        checkRateLimit(request, currentUser);
        enforceScanLimits(url, active, currentUser, request);
    }

    /**
     * Travas de custo: scan ativo exige login, guest consome a cota diária por IP e
     * usuário consome a cota do plano (e, no ativo, passa pela trava de plano e de
     * domínio verificado na conta).
     *
     * Estava duplicado em /scan e /scan/async e ausente em /scan/report e
     * /scan/report/pdf — o que fazia dos dois últimos um bypass completo dos limites.
     */
    public void enforceScanLimits(String url, boolean active,
                                  AppUser currentUser, HttpServletRequest request) {
        if (active && currentUser == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "Scan ativo requer autenticação. Faça login ou solicite um convite.");
        }
        if (currentUser == null) {
            guestRateLimitService.checkAndIncrement(clientIpResolver.resolve(request));
        } else {
            if (active) planLimitService.checkActiveScan(currentUser, url);
            planLimitService.checkAndIncrementDailyScan(currentUser);
        }
    }

    /** Requisições por minuto, por usuário (ou por IP, para guest). */
    public void checkRateLimit(HttpServletRequest request, AppUser currentUser) {
        if (!rateLimitService.allow(clientIpResolver.resolve(request), currentUser)) {
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,
                    "Muitas requisições. " +
                            (currentUser == null
                                    ? "Limite de " + RateLimitService.GUEST_RPM
                                    + " requests/min para visitantes."
                                    : "Tente novamente em alguns segundos.")
            );
        }
    }
}
