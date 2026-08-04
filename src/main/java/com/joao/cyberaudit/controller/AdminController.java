package com.joao.cyberaudit.controller;

import com.joao.cyberaudit.dto.*;
import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.AccountType;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.AuditAction;
import com.joao.cyberaudit.model.Domain;
import com.joao.cyberaudit.model.Role;
import com.joao.cyberaudit.repository.AccountRepository;
import com.joao.cyberaudit.repository.AppUserRepository;
import com.joao.cyberaudit.repository.DomainRepository;
import com.joao.cyberaudit.service.AuditService;
import com.joao.cyberaudit.service.ExecutivePdfReportService;
import com.joao.cyberaudit.service.InviteService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.HexFormat;

@RestController
@RequestMapping("/admin")
public class AdminController {

    private final AppUserRepository      userRepository;
    private final AccountRepository      accountRepository;
    private final InviteService          inviteService;
    private final AuditService           auditService;
    private final DomainRepository       domainRepository;
    private final ExecutivePdfReportService pdfReportService;

    public AdminController(AppUserRepository userRepository,
                           AccountRepository accountRepository,
                           InviteService inviteService,
                           AuditService auditService,
                           DomainRepository domainRepository,
                           ExecutivePdfReportService pdfReportService) {
        this.userRepository    = userRepository;
        this.accountRepository = accountRepository;
        this.inviteService     = inviteService;
        this.auditService      = auditService;
        this.domainRepository  = domainRepository;
        this.pdfReportService  = pdfReportService;
    }

    @GetMapping("/users")
    public List<UserManagementDto> listUsers(@AuthenticationPrincipal AppUser caller) {
        requireOwner(caller);
        // findAll() devolvia TODOS os usuários da plataforma. Como /auth/register é
        // público e cria o usuário já como OWNER, qualquer pessoa se cadastrava e
        // listava nome/e-mail/role de todos os clientes.
        return userRepository.findByAccount(requireAccount(caller))
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

        AppUser target = findUser(id, caller);

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

        AppUser target = findUser(id, caller);

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
        AppUser target = findUser(id, caller);
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
        return inviteService.findPending(caller);
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

    /**
     * Ativa, desativa ou regenera o token da página de status pública.
     * Body: { "enabled": true } para ativar/regenerar, { "enabled": false } para desativar.
     * Apenas OWNER.
     */
    @PostMapping("/account/status-page")
    public ResponseEntity<Map<String, Object>> toggleStatusPage(
            @RequestBody Map<String, Boolean> body,
            @AuthenticationPrincipal AppUser caller) {

        requireOwner(caller);
        Account account = caller.getAccount();
        if (account == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Conta não encontrada.");
        }

        boolean enabled = Boolean.TRUE.equals(body.get("enabled"));
        if (enabled) {
            // Gera token de 32 bytes (64 chars hex)
            byte[] bytes = new byte[32];
            new java.security.SecureRandom().nextBytes(bytes);
            String token = HexFormat.of().formatHex(bytes);
            account.setPublicStatusToken(token);
        } else {
            account.setPublicStatusToken(null);
        }
        accountRepository.save(account);

        return ResponseEntity.ok(Map.of(
                "enabled", enabled,
                "token", account.getPublicStatusToken() != null ? account.getPublicStatusToken() : ""
        ));
    }

    /**
     * Gera e retorna um PDF executivo consolidado da conta.
     * Disponível para OWNER e ADMIN.
     *
     * @param scope  DOMAINS (padrão) | TEAM_SCANS | BOTH
     * @param from   data inicial no formato yyyy-MM-dd (opcional)
     * @param to     data final   no formato yyyy-MM-dd (opcional)
     */
    @GetMapping("/report/executive-pdf")
    public ResponseEntity<byte[]> executivePdf(
            @AuthenticationPrincipal AppUser caller,
            @RequestParam(defaultValue = "DOMAINS") String scope,
            @RequestParam(required = false) String from,
            @RequestParam(required = false) String to) {

        if (caller.getRole() != Role.OWNER && caller.getRole() != Role.ADMIN) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "Acesso restrito a OWNER ou ADMIN.");
        }

        Account account = caller.getAccount();
        if (account == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Conta não encontrada.");
        }

        ExecutivePdfReportService.ReportScope reportScope;
        try {
            reportScope = ExecutivePdfReportService.ReportScope.valueOf(scope.toUpperCase());
        } catch (IllegalArgumentException e) {
            reportScope = ExecutivePdfReportService.ReportScope.DOMAINS;
        }

        LocalDate dateFrom = from != null ? LocalDate.parse(from) : null;
        LocalDate dateTo   = to   != null ? LocalDate.parse(to)   : null;

        List<Domain> domains = domainRepository.findByAccountOrderByCreatedAtDesc(account);
        byte[] pdfBytes = pdfReportService.generate(account, domains, reportScope, dateFrom, dateTo);

        String suffix = from != null && to != null ? "_" + from + "_a_" + to
                      : from != null ? "_desde_" + from
                      : to   != null ? "_ate_" + to
                      : "";
        String filename = "cyberaudit-report-" + scope.toLowerCase() + suffix + ".pdf";

        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_PDF)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"")
                .body(pdfBytes);
    }

    private void requireOwner(AppUser caller) {
        if (caller.getRole() != Role.OWNER) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "Acesso restrito ao OWNER.");
        }
    }

    private Account requireAccount(AppUser caller) {
        Account account = caller.getAccount();
        if (account == null) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "Usuário sem conta associada.");
        }
        return account;
    }

    /**
     * Usuário alvo, obrigatoriamente da MESMA conta do chamador.
     *
     * Sem o filtro de conta, um OWNER podia alterar role, desativar e reativar
     * usuários de qualquer outra conta apenas conhecendo o UUID. Alvo de outra
     * conta responde 404 — não confirma existência.
     */
    private AppUser findUser(UUID id, AppUser caller) {
        Account account = requireAccount(caller);
        return userRepository.findById(id)
                .filter(u -> u.getAccount() != null
                        && u.getAccount().getId().equals(account.getId()))
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Usuário não encontrado."));
    }
}