package com.joao.cyberaudit.service;

import com.joao.cyberaudit.dto.InviteAcceptRequest;
import com.joao.cyberaudit.dto.InviteDto;
import com.joao.cyberaudit.dto.InviteRequest;
import com.joao.cyberaudit.model.*;
import com.joao.cyberaudit.repository.AppUserRepository;
import com.joao.cyberaudit.repository.InviteRepository;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Service
public class InviteService {

    private final InviteRepository  inviteRepository;
    private final AppUserRepository userRepository;
    private final PasswordEncoder   passwordEncoder;

    public InviteService(InviteRepository inviteRepository,
                         AppUserRepository userRepository,
                         PasswordEncoder passwordEncoder) {
        this.inviteRepository = inviteRepository;
        this.userRepository   = userRepository;
        this.passwordEncoder  = passwordEncoder;
    }

    @Transactional
    public InviteDto create(InviteRequest req, AppUser inviter) {

        // Somente contas COMPANY podem ter múltiplos usuários
        if (inviter.getAccount() == null ||
                inviter.getAccount().getType() != AccountType.COMPANY) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "Convites de usuários estão disponíveis apenas para contas Empresa.");
        }

        if (inviter.getRole() == Role.ADMIN && req.getRole() != Role.FREE_EMPLOYEE) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "Admins só podem convidar funcionários.");
        }

        if (req.getRole() == Role.OWNER) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "Não é possível convidar outro OWNER.");
        }

        if (userRepository.existsByEmail(req.getEmail().toLowerCase().trim())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Já existe um usuário com esse email.");
        }

        if (inviteRepository.existsByEmailAndAcceptedFalse(
                req.getEmail().toLowerCase().trim())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Já existe um convite pendente para esse email.");
        }

        String token = UUID.randomUUID().toString();

        Invite invite = Invite.builder()
                .name(req.getName())
                .email(req.getEmail().toLowerCase().trim())
                .token(token)
                .role(req.getRole())
                .jobTitle(req.getJobTitle())
                .invitedBy(inviter)
                .account(inviter.getAccount())
                .accepted(false)
                .expiresAt(LocalDateTime.now().plusHours(48))
                .createdAt(LocalDateTime.now())
                .build();

        inviteRepository.save(invite);

        InviteDto dto = InviteDto.from(invite);
        dto.setAcceptLink("/auth/accept-invite/" + token);
        return dto;
    }

    @Transactional
    public void accept(String token, InviteAcceptRequest req) {
        Invite invite = inviteRepository.findByToken(token)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Convite não encontrado."));

        if (invite.isAccepted()) {
            throw new ResponseStatusException(HttpStatus.GONE,
                    "Este convite já foi utilizado.");
        }

        if (invite.isExpired()) {
            throw new ResponseStatusException(HttpStatus.GONE,
                    "Este convite expirou. Solicite um novo ao administrador.");
        }

        if (userRepository.existsByEmail(invite.getEmail())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Já existe um usuário com esse email.");
        }

        if (!req.isTermsAccepted()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "É necessário aceitar os Termos de Uso e Política de Privacidade.");
        }
        PasswordPolicy.validate(req.getPassword());
        PasswordPolicy.validateIdentity(req.getName(), invite.getEmail());

        String name = (req.getName() != null && !req.getName().isBlank())
                ? req.getName() : invite.getName();

        AppUser newUser = AppUser.builder()
                .name(name)
                .email(invite.getEmail())
                .passwordHash(passwordEncoder.encode(req.getPassword()))
                .role(invite.getRole())
                .jobTitle(invite.getJobTitle())
                .active(true)
                .createdAt(LocalDateTime.now())
                .account(invite.getAccount())
                .invitedBy(invite.getInvitedBy())
                .termsAccepted(true)
                .termsAcceptedAt(java.time.LocalDateTime.now())
                .build();

        userRepository.save(newUser);

        invite.setAccepted(true);
        invite.setAcceptedAt(LocalDateTime.now());
        inviteRepository.save(invite);
    }

    /** Convites pendentes da conta do chamador — nunca de outras contas. */
    public List<InviteDto> findPending(AppUser caller) {
        if (caller == null || caller.getAccount() == null) return List.of();
        return inviteRepository.findPendingByAccount(caller.getAccount(), LocalDateTime.now())
                .stream()
                .map(invite -> {
                    InviteDto dto = InviteDto.from(invite);
                    // Inclui o link na listagem — só OWNER da própria conta chega aqui
                    dto.setAcceptLink("/auth/accept-invite/" + invite.getToken());
                    return dto;
                })
                .toList();
    }

    @Transactional
    public void revoke(UUID inviteId, AppUser caller) {
        Invite invite = inviteRepository.findById(inviteId)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Convite não encontrado."));

        // Convite de outra conta responde 404 — não confirma nem a existência.
        if (caller == null || caller.getAccount() == null
                || invite.getAccount() == null
                || !invite.getAccount().getId().equals(caller.getAccount().getId())) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Convite não encontrado.");
        }

        if (invite.isAccepted()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Convite já aceito — não pode ser revogado.");
        }

        if (caller.getRole() == Role.ADMIN &&
                !invite.getInvitedBy().getId().equals(caller.getId())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "Você só pode revogar convites que criou.");
        }

        inviteRepository.delete(invite);
    }

    @Scheduled(cron = "0 0 2 * * *")
    @Transactional
    public void cleanExpiredInvites() {
        inviteRepository.deleteExpired(LocalDateTime.now());
    }
}