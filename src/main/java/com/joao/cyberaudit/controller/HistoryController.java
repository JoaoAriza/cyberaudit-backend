package com.joao.cyberaudit.controller;

import com.joao.cyberaudit.model.ScanResult;
import com.joao.cyberaudit.model.ScanSummary;
import com.joao.cyberaudit.service.ScanHistoryService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/history")
public class HistoryController {

    private final ScanHistoryService historyService;

    public HistoryController(ScanHistoryService historyService) {
        this.historyService = historyService;
    }

    @GetMapping("/recent")
    public List<ScanSummary> recent() {
        return historyService.findRecent(20).stream()
                .map(ScanSummary::from)
                .toList();
    }

    @GetMapping("/{host}")
    public List<ScanSummary> byHost(@PathVariable String host) {
        return historyService.findByHost(host, 50).stream()
                .map(ScanSummary::from)
                .toList();
    }

    @GetMapping("/{id}/result")
    public ResponseEntity<ScanResult> result(@PathVariable UUID id) {
        return historyService.getResult(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }
}