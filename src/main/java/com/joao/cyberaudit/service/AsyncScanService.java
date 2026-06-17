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
    private final ScanOrchestrator  scanOrchestrator;
    private final EmailService      emailService;
    private final AppUserRepository appUserRepository;

    public AsyncScanService(ScanOrchestrator scanOrchestrator,
                            EmailService emailService,
                            AppUserRepository appUserRepository) {
        this.scanOrchestrator  = scanOrchestrator;
        this.emailService      = emailService;
        this.appUserRepository = appUserRepository;
    }

    public String submit(String url, boolean active, AppUser currentUser,
                         boolean refresh, boolean notify) {
        String scanId = UUID.randomUUID().toString();
        statusMap.put(scanId, new AsyncScanStatus(scanId, State.PENDING, null, null));
        executeAsync(scanId, url, active, currentUser, refresh, notify);
        return scanId;
    }

    /** Overload sem notify para compatibilidade (chamadas internas sem notificação) */
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
            // Re-fetch user with account eagerly loaded within this async thread's JPA session.
            // The currentUser passed from the HTTP thread has a detached lazy proxy for account;
            // calling getAccount() here would cause "pk is null" NPE (Hibernate detached proxy).
            if (currentUser != null) {
                currentUser = appUserRepository
                        .findByEmailWithAccount(currentUser.getEmail())
                        .orElse(currentUser);
            }

            ScanResult result = scanOrchestrator.execute(url, active, currentUser, refresh);
            statusMap.put(scanId, new AsyncScanStatus(scanId, State.DONE, result, null));

            // Notificação por email — só se solicitado e usuário autenticado
            if (notify && currentUser != null) {
                emailService.sendScanComplete(
                        currentUser.getEmail(),
                        currentUser.getName(),
                        result);
            }
        } catch (Exception e) {
            statusMap.put(scanId, new AsyncScanStatus(scanId, State.ERROR, null, e.getMessage()));
        }
    }
}
