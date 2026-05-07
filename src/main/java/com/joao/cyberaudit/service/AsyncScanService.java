package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.AsyncScanStatus;
import com.joao.cyberaudit.model.AsyncScanStatus.State;
import com.joao.cyberaudit.model.ScanResult;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class AsyncScanService {
    
    private final ConcurrentHashMap<String, AsyncScanStatus> statusMap = new ConcurrentHashMap<>();

    private final ScanOrchestrator scanOrchestrator;

    public AsyncScanService(ScanOrchestrator scanOrchestrator) {
        this.scanOrchestrator = scanOrchestrator;
    }

    public String submit(String url, boolean active) {
        String scanId = UUID.randomUUID().toString();

        statusMap.put(scanId, new AsyncScanStatus(scanId, State.PENDING, null, null));
        executeAsync(scanId, url, active);

        return scanId;
    }

    public AsyncScanStatus getStatus(String scanId) {
        return statusMap.get(scanId);
    }

    @Async
    public void executeAsync(String scanId, String url, boolean active) {
        statusMap.put(scanId, new AsyncScanStatus(scanId, State.RUNNING, null, null));
        try {
            ScanResult result = scanOrchestrator.execute(url, active);
            statusMap.put(scanId, new AsyncScanStatus(scanId, State.DONE, result, null));
        } catch (Exception e) {
            statusMap.put(scanId, new AsyncScanStatus(scanId, State.ERROR, null, e.getMessage()));
        }
    }
}