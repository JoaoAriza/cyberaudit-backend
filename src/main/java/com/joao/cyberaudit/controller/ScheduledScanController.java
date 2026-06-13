package com.joao.cyberaudit.controller;

import com.joao.cyberaudit.dto.ScheduledScanDto;
import com.joao.cyberaudit.dto.ScheduledScanRequest;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.service.ScheduledScanService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/scheduled-scans")
public class ScheduledScanController {

    private final ScheduledScanService service;

    public ScheduledScanController(ScheduledScanService service) {
        this.service = service;
    }

    @GetMapping
    public List<ScheduledScanDto> list() {
        return service.listByUser(requireUser());
    }

    @PostMapping
    public ResponseEntity<ScheduledScanDto> create(@RequestBody ScheduledScanRequest req) {
        ScheduledScanDto dto = service.create(req, requireUser());
        return ResponseEntity.status(HttpStatus.CREATED).body(dto);
    }

    @PatchMapping("/{id}/toggle")
    public ScheduledScanDto toggle(@PathVariable UUID id) {
        return service.toggleEnabled(id, requireUser());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable UUID id) {
        service.delete(id, requireUser());
        return ResponseEntity.noContent().build();
    }

    private AppUser requireUser() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()
                || auth.getPrincipal() instanceof String) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "Autenticação necessária para gerenciar scans agendados.");
        }
        return (AppUser) auth.getPrincipal();
    }
}
