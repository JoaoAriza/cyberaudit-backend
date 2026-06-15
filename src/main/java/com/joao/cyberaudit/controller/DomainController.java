package com.joao.cyberaudit.controller;

import com.joao.cyberaudit.dto.DomainDto;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.service.DomainService;
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

    private final DomainService domainService;

    public DomainController(DomainService domainService) {
        this.domainService = domainService;
    }

    /** Lista todos os domínios da conta do usuário autenticado. */
    @GetMapping
    public List<DomainDto> list(@AuthenticationPrincipal AppUser user) {
        return domainService.list(user);
    }

    /** Cadastra um novo domínio. Body: { "host": "example.com" } */
    @PostMapping
    public ResponseEntity<DomainDto> add(
            @RequestBody Map<String, String> body,
            @AuthenticationPrincipal AppUser user) {

        String host = body.get("host");
        DomainDto created = domainService.add(host, user);
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    /** Remove um domínio da conta. */
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> remove(
            @PathVariable UUID id,
            @AuthenticationPrincipal AppUser user) {

        domainService.remove(id, user);
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
        return ResponseEntity.ok(result);
    }
}
