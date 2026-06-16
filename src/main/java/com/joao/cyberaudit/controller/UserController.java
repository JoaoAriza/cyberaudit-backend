package com.joao.cyberaudit.controller;

import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.Role;
import com.joao.cyberaudit.repository.AccountRepository;
import com.joao.cyberaudit.repository.AppUserRepository;
import com.joao.cyberaudit.repository.DomainRepository;
import com.joao.cyberaudit.repository.InviteRepository;
import com.joao.cyberaudit.repository.OtpCodeRepository;
import com.joao.cyberaudit.repository.ScheduledScanRepository;
import com.joao.cyberaudit.service.DataExportService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;

/**
 * Endpoints de dados pessoais do usuário autenticado (LGPD).
 */
@RestController
@RequestMapping("/user")
public class UserController {

    private final DataExportService      dataExportService;
    private final AppUserRepository      userRepository;
    private final AccountRepository      accountRepository;
    private final ScheduledScanRepository scheduledScanRepository;
    private final InviteRepository       inviteRepository;
    private final DomainRepository       domainRepository;
    private final OtpCodeRepository      otpCodeRepository;

    public UserController(DataExportService dataExportService,
                          AppUserRepository userRepository,
                          AccountRepository accountRepository,
                          ScheduledScanRepository scheduledScanRepository,
                          InviteRepository inviteRepository,
                          DomainRepository domainRepository,
                          OtpCodeRepository otpCodeRepository) {
        this.dataExportService       = dataExportService;
        this.userRepository          = userRepository;
        this.accountRepository       = accountRepository;
        this.scheduledScanRepository = scheduledScanRepository;
        this.inviteRepository        = inviteRepository;
        this.domainRepository        = domainRepository;
        this.otpCodeRepository       = otpCodeRepository;
    }

    /**
     * LGPD Art. 18 — Portabilidade.
     * Retorna todos os dados pessoais do usuário em JSON.
     */
    @GetMapping("/data-export")
    public ResponseEntity<Map<String, Object>> exportData(
            @AuthenticationPrincipal AppUser user) {
        return ResponseEntity.ok(dataExportService.exportUserData(user));
    }

    /**
     * LGPD Art. 18 — Direito ao esquecimento.
     * Remove a conta e dados pessoais do usuário autenticado.
     *
     * Regras:
     * - Qualquer usuário pode excluir sua própria conta.
     * - OWNER só pode excluir se for o único usuário da conta (evita conta órfã com dados).
     * - Ao excluir, são removidos: agendamentos, OTPs, convites criados pelo usuário.
     * - OWNER também remove: domínios da conta, todos os convites da conta, e a própria conta.
     */
    @DeleteMapping("/account")
    @Transactional
    public ResponseEntity<Map<String, String>> deleteAccount(
            @AuthenticationPrincipal AppUser user) {

        boolean isOwner = user.getRole() == Role.OWNER;

        if (isOwner && user.getAccount() != null) {
            long activeUsersInAccount = userRepository
                    .findAll()
                    .stream()
                    .filter(u -> u.getAccount() != null
                            && u.getAccount().getId().equals(user.getAccount().getId())
                            && u.isActive()
                            && !u.getId().equals(user.getId()))
                    .count();

            if (activeUsersInAccount > 0) {
                throw new ResponseStatusException(HttpStatus.CONFLICT,
                        "Transfira a propriedade da conta para outro usuário antes de excluir sua conta.");
            }
        }

        // 1. OTPs do usuário
        otpCodeRepository.deleteByUserId(user.getId());

        // 2. Agendamentos do usuário
        scheduledScanRepository.deleteByUser(user);

        // 3. Convites criados por este usuário
        inviteRepository.deleteByInvitedById(user.getId());

        if (isOwner && user.getAccount() != null) {
            var account = user.getAccount();

            // 4. Domínios da conta
            domainRepository.findByAccountOrderByCreatedAtDesc(account)
                    .forEach(domainRepository::delete);

            // 5. Todos os convites da conta
            inviteRepository.deleteByAccountId(account.getId());

            // 6. Usuário (OWNER)
            userRepository.delete(user);

            // 7. Conta
            accountRepository.delete(account);

        } else {
            // Apenas o usuário
            userRepository.delete(user);
        }

        return ResponseEntity.ok(Map.of(
                "message", "Conta excluída com sucesso. Seus dados foram removidos."
        ));
    }
}
