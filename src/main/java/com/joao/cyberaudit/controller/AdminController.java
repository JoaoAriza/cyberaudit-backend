package com.joao.cyberaudit.controller;

import com.joao.cyberaudit.dto.*;
import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.AccountType;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.AuditAction;
import com.joao.cyberaudit.model.Role;
import com.joao.cyberaudit.repository.AccountRepository;
import com.joao.cyberaudit.repository.AppUserRepository;
import com.joao.cyberaudit.service.AuditService;
import com.joao.cyberaudit.service.InviteService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/admin")
public class AdminController {

    private final AppUserRepository userRepository;
    private final AccountRepository accountRepository;
    private final InviteService     inviteService;
    private final AuditService      auditService;

    public AdminController(AppUserRepository userRepository,
                           AccountRepository accountRepository,
                           InviteService inviteService,
                           AuditService auditService) {
        this.userRepository    = userRepository;
        this.accountRepository = accountRepository;
        this.inviteService     = inviteService;
        this.auditService      = auditService;
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

        Role oldRole = target.getRole();
        target.setRole(req.getRole());
        userRepository.save(target);
        auditService.log(caller, AuditAction.USER_ROLE_CHANGED,
                target.getEmail() + ": " + oldRole + " → " + req.getRole());
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
        auditService.log(caller, AuditAction.USER_DEACTIVATED, target.getEmail());
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
        auditService.log(caller, AuditAction.USER_REACTIVATED, target.getEmail());
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
        auditService.log(caller, AuditAction.USER_INVITED,
                req.getEmail() + " (" + req.getRole() + ")");
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

    /** Alterna require2fa da conta. Apenas OWNER. */
    @PutMapping("/account/require2fa")
    public ResponseEntity<Map<String, Object>> setRequire2fa(
            @RequestBody Map<String, Boolean> body,
            @AuthenticationPrincipal AppUser caller) {

        requireOwner(caller);
        Account account = caller.getAccount();
        if (account == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Conta não encontrada.");
        }
        boolean require = Boolean.TRUE.equals(body.get("require2fa"));
        account.setRequire2fa(require);
        accountRepository.save(account);
        auditService.log(caller, AuditAction.REQUIRE_2FA_CHANGED, "require2fa=" + require);
        return ResponseEntity.ok(Map.of("require2fa", require));
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