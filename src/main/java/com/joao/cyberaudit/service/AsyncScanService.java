package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.AsyncScanStatus;
import com.joao.cyberaudit.model.AsyncScanStatus.State;
import com.joao.cyberaudit.model.ScanResult;
import com.joao.cyberaudit.repository.AppUserRepository;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class AsyncScanService {

    private final ConcurrentHashMap<String, AsyncScanStatus> statusMap = new ConcurrentHashMap<>();
    private final ScanOrchestrator       scanOrchestrator;
    private final EmailService           emailService;
    private final AppUserRepository       appUserRepository;
    private final ScanEntitlementService scanEntitlement;

    public AsyncScanService(ScanOrchestrator scanOrchestrator,
                            EmailService emailService,
                            AppUserRepository appUserRepository,
                            ScanEntitlementService scanEntitlement) {
        this.scanOrchestrator  = scanOrchestrator;
        this.emailService      = emailService;
        this.appUserRepository = appUserRepository;
        this.scanEntitlement   = scanEntitlement;
    }

    public String submit(String url, boolean active, AppUser currentUser,
                         boolean refresh, boolean notify) {
        String scanId = UUID.randomUUID().toString();
        statusMap.put(scanId, new AsyncScanStatus(scanId, State.PENDING, null, null));
        executeAsync(scanId, url, active, currentUser, refresh, notify);
        return scanId;
    }

    public String submit(String url, boolean active, AppUser currentUser, boolean refresh) {
        return submit(url, active, currentUser, refresh, false);
    }

    public AsyncScanStatus getStatus(String scanId) {
        return statusMap.get(scanId);
    }

    @Async
    public void executeAsync(String scanId, String url, boolean active,
                             AppUser currentUser, boolean refresh, boolean notify) {
        statusMap.put(scanId, new AsyncScanStatus(scanId, State.RUNNING, null, null));
        try {
            // Re-fetch user WITH eager account (JOIN FETCH) in the async thread's own JPA session.
            // The principal from Spring Security is a detached entity — its lazy account proxy
            // cannot be initialized outside the original session. findByEmailWithAccount uses
            // LEFT JOIN FETCH u.account to avoid LazyInitializationException / NPE on pk.
            if (currentUser != null) {
                currentUser = appUserRepository
                        .findByEmailWithAccount(currentUser.getEmail())
                        .orElse(null);
            }

            ScanResult result = scanOrchestrator.execute(url, active, currentUser, refresh);

            // E-mail pessoal (ao próprio usuário) usa o resultado completo.
            if (notify && currentUser != null && result != null) {
                emailService.sendScanComplete(
                        currentUser.getEmail(),
                        currentUser.getName(),
                        result);
            }

            // A UI recebe o resultado já com gating por plano (guest/FREE não veem
            // impacto/correção/breakdown). applyEntitlement nunca muta o cache.
            statusMap.put(scanId, new AsyncScanStatus(scanId, State.DONE,
                    scanEntitlement.applyEntitlement(result, currentUser), null));
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            statusMap.put(scanId, new AsyncScanStatus(scanId, State.ERROR, null,
                    "Erro ao executar scan: " + msg));
        }
    }
}
