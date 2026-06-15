package com.joao.cyberaudit.controller;

import com.joao.cyberaudit.dto.*;
import com.joao.cyberaudit.model.AccountType;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.Role;
import com.joao.cyberaudit.repository.AppUserRepository;
import com.joao.cyberaudit.service.InviteService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/admin")
public class AdminController {

    private final AppUserRepository userRepository;
    private final InviteService     inviteService;

    public AdminController(AppUserRepository userRepository,
                           InviteService inviteService) {
        this.userRepository = userRepository;
        this.inviteService  = inviteService;
    }

    @GetMapping("/users")
    public List<UserManagementDto> listUsers(@AuthenticationPrincipal AppUser caller) {
        requireOwner(caller);
        return userRepository.findAll()
                .stream()
                .map(UserManagementDto::from)
                .toList();
    }

    @PutMapping("/users/{id}/role")
    public ResponseEntity<UserManagementDto> updateRole(
            @PathVariable UUID id,
            @RequestBody UpdateRoleRequest req,
            @AuthenticationPrincipal AppUser caller) {

        requireOwner(caller);

        if (req.getRole() == Role.OWNER) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "Não é possível promover outro usuário a OWNER.");
        }

        AppUser target = findUser(id);

        if (target.getRole() == Role.OWNER) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "Não é possível alterar o role do OWNER.");
        }

        target.setRole(req.getRole());
        userRepository.save(target);
        return ResponseEntity.ok(UserManagementDto.from(target));
    }

    @DeleteMapping("/users/{id}")
    public ResponseEntity<Void> deactivateUser(
            @PathVariable UUID id,
            @AuthenticationPrincipal AppUser caller) {

        requireOwner(caller);

        AppUser target = findUser(id);

        if (target.getRole() == Role.OWNER) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "Não é possível desativar o OWNER.");
        }

        if (target.getId().equals(caller.getId())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "Você não pode desativar sua própria conta.");
        }

        target.setActive(false);
        userRepository.save(target);
        return ResponseEntity.noContent().build();
    }

    @PutMapping("/users/{id}/reactivate")
    public ResponseEntity<UserManagementDto> reactivateUser(
            @PathVariable UUID id,
            @AuthenticationPrincipal AppUser caller) {

        requireOwner(caller);
        AppUser target = findUser(id);
        target.setActive(true);
        userRepository.save(target);
        return ResponseEntity.ok(UserManagementDto.from(target));
    }

    @PostMapping("/invite")
    public ResponseEntity<InviteDto> createInvite(
            @RequestBody InviteRequest req,
            @AuthenticationPrincipal AppUser caller) {

        if (caller.getRole() == Role.FREE_EMPLOYEE) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "Funcionários não podem criar convites.");
        }

        // Conta INDIVIDUAL não pode convidar usuários (verificado também no InviteService)
        if (caller.getAccount() == null ||
                caller.getAccount().getType() != AccountType.COMPANY) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "Convites estão disponíveis apenas para contas Empresa.");
        }

        InviteDto dto = inviteService.create(req, caller);
        return ResponseEntity.status(HttpStatus.CREATED).body(dto);
    }

    @GetMapping("/invites")
    public List<InviteDto> listInvites(@AuthenticationPrincipal AppUser caller) {
        requireOwner(caller);
        return inviteService.findPending();
    }

    @DeleteMapping("/invites/{id}")
    public ResponseEntity<Void> revokeInvite(
            @PathVariable UUID id,
            @AuthenticationPrincipal AppUser caller) {

        if (caller.getRole() == Role.FREE_EMPLOYEE) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "Sem permissão.");
        }

        inviteService.revoke(id, caller);
        return ResponseEntity.noContent().build();
    }

    private void requireOwner(AppUser caller) {
        if (caller.getRole() != Role.OWNER) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "Acesso restrito ao OWNER.");
        }
    }

    private AppUser findUser(UUID id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Usuário não encontrado."));
    }
}