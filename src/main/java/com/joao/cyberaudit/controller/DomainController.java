package com.joao.cyberaudit.controller;

import com.joao.cyberaudit.dto.DomainDto;
import com.joao.cyberaudit.dto.SubdomainInfo;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.AuditAction;
import com.joao.cyberaudit.service.AuditService;
import com.joao.cyberaudit.service.DomainService;
import com.joao.cyberaudit.service.PlanLimitService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/domains")
public class DomainController {

    private final DomainService    domainService;
    private final AuditService     auditService;
    private final PlanLimitService planLimitService;

    public DomainController(DomainService domainService,
                            AuditService auditService,
                            PlanLimitService planLimitService) {
        this.domainService    = domainService;
        this.auditService     = auditService;
        this.planLimitService = planLimitService;
    }

    /** Lista todos os domínios da conta do usuário autenticado. */
    @GetMapping
    public List<DomainDto> list(@AuthenticationPrincipal AppUser user) {
        return domainService.list(user);
    }

    /** Cadastra um novo domínio (PRO+). Body: { "host": "example.com" } */
    @PostMapping
    public ResponseEntity<DomainDto> add(
            @RequestBody Map<String, String> body,
            @AuthenticationPrincipal AppUser user) {

        planLimitService.checkDomainRegistration(user);

        String host = body.get("host");
        DomainDto created = domainService.add(host, user);
        auditService.log(user, AuditAction.DOMAIN_ADDED, host);
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    /** Remove um domínio da conta. */
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> remove(
            @PathVariable UUID id,
            @AuthenticationPrincipal AppUser user) {

        domainService.remove(id, user);
        auditService.log(user, AuditAction.DOMAIN_REMOVED, "id=" + id);
        return ResponseEntity.noContent().build();
    }

    /**
     * Tenta verificar a propriedade do domínio via
     * https://{host}/.well-known/cyberaudit.txt
     */
    @PostMapping("/{id}/verify")
    public ResponseEntity<DomainDto> verify(
            @PathVariable UUID id,
            @AuthenticationPrincipal AppUser user) {

        DomainDto result = domainService.verify(id, user);
        auditService.log(user, AuditAction.DOMAIN_VERIFIED, result.getHost());
        return ResponseEntity.ok(result);
    }

    /**
     * Enumera subdomínios via Certificate Transparency + DNS probe.
     * Requer: domínio verificado + conta EMPRESA (ou OWNER/ADMIN).
     * Pode demorar 20-60s dependendo da quantidade de subdomínios.
     */
    @PostMapping("/{id}/enumerate")
    public ResponseEntity<List<SubdomainInfo>> enumerate(
            @PathVariable UUID id,
            @AuthenticationPrincipal AppUser user) {

        List<SubdomainInfo> results = domainService.enumerate(id, user);
        auditService.log(user, AuditAction.DOMAIN_VERIFIED, "enumerate:id=" + id + " found=" + results.size());
        return ResponseEntity.ok(results);
    }
}
