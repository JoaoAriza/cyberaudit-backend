package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.Role;
import com.joao.cyberaudit.repository.*;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.UUID;

/**
 * Exclusão de conta / usuário — LGPD Art. 18, direito ao esquecimento.
 *
 * A versão anterior apagava apenas OTPs, agendamentos, convites e domínios, e
 * então tentava remover a conta. Como `scan_records`, `api_keys`, `subscriptions`
 * e `feedbacks` têm FK para `accounts` (sem ON DELETE CASCADE), a exclusão
 * estourava com violação de integridade — e, dado que TODO scan autenticado grava
 * um `scan_records`, na prática nenhuma conta que já tivesse usado o produto
 * conseguia ser excluída. O usuário recebia um erro genérico e os dados ficavam.
 *
 * A ordem abaixo respeita as dependências: tudo que aponta para o usuário/conta
 * sai antes deles.
 *
 * O que NÃO é removido, deliberadamente: `audit_logs`. Eles guardam o accountId
 * como UUID solto (sem FK) e existem para rastreabilidade de segurança — a base
 * legal é o legítimo interesse, não o consentimento. Contêm e-mail e nome, então
 * a política de retenção deles deve estar descrita na Política de Privacidade.
 */
@Service
public class AccountDeletionService {

    private final AppUserRepository        userRepository;
    private final AccountRepository        accountRepository;
    private final ScheduledScanRepository  scheduledScanRepository;
    private final InviteRepository         inviteRepository;
    private final DomainRepository         domainRepository;
    private final OtpCodeRepository        otpCodeRepository;
    private final ScanRecordRepository     scanRecordRepository;
    private final ApiKeyRepository         apiKeyRepository;
    private final SubscriptionRepository   subscriptionRepository;
    private final FeedbackRepository       feedbackRepository;

    public AccountDeletionService(AppUserRepository userRepository,
                                  AccountRepository accountRepository,
                                  ScheduledScanRepository scheduledScanRepository,
                                  InviteRepository inviteRepository,
                                  DomainRepository domainRepository,
                                  OtpCodeRepository otpCodeRepository,
                                  ScanRecordRepository scanRecordRepository,
                                  ApiKeyRepository apiKeyRepository,
                                  SubscriptionRepository subscriptionRepository,
                                  FeedbackRepository feedbackRepository) {
        this.userRepository         = userRepository;
        this.accountRepository      = accountRepository;
        this.scheduledScanRepository = scheduledScanRepository;
        this.inviteRepository       = inviteRepository;
        this.domainRepository       = domainRepository;
        this.otpCodeRepository      = otpCodeRepository;
        this.scanRecordRepository   = scanRecordRepository;
        this.apiKeyRepository       = apiKeyRepository;
        this.subscriptionRepository = subscriptionRepository;
        this.feedbackRepository     = feedbackRepository;
    }

    /** Identidade preservada para o registro de auditoria, que é gravado após a exclusão. */
    public record DeletedIdentity(UUID accountId, String email, String name, boolean wasOwner) {}

    @Transactional
    public DeletedIdentity deleteOwnAccount(AppUser user) {
        Account account = user.getAccount();
        boolean isOwner = user.getRole() == Role.OWNER;

        if (isOwner && account != null) {
            long otherActiveUsers = userRepository.findByAccount(account).stream()
                    .filter(u -> u.isActive() && !u.getId().equals(user.getId()))
                    .count();
            if (otherActiveUsers > 0) {
                throw new ResponseStatusException(HttpStatus.CONFLICT,
                        "Transfira a propriedade da conta para outro usuário antes de excluir sua conta.");
            }
        }

        DeletedIdentity identity = new DeletedIdentity(
                account != null ? account.getId() : null,
                user.getEmail(), user.getName(), isOwner);

        // ── Dependências do USUÁRIO ──────────────────────────────────────────
        otpCodeRepository.deleteByUserId(user.getId());
        scheduledScanRepository.deleteByUser(user);
        inviteRepository.deleteByInvitedById(user.getId());
        apiKeyRepository.deleteByCreatedBy(user);
        feedbackRepository.deleteByUser(user);

        // Feedback que este usuário revisou: solta a referência em vez de apagar
        // o feedback de outra pessoa.
        feedbackRepository.findByReviewedBy(user).forEach(f -> {
            f.setReviewedBy(null);
            feedbackRepository.save(f);
        });

        // Usuários convidados por este: a referência é opcional, então só some.
        userRepository.findByInvitedBy(user).forEach(u -> {
            u.setInvitedBy(null);
            userRepository.save(u);
        });

        if (isOwner && account != null) {
            // ── Dependências da CONTA ────────────────────────────────────────
            scanRecordRepository.deleteByAccount(account);
            apiKeyRepository.deleteByAccount(account);
            subscriptionRepository.deleteByAccount(account);
            feedbackRepository.deleteByAccount(account);
            domainRepository.findByAccountOrderByCreatedAtDesc(account)
                    .forEach(domainRepository::delete);
            inviteRepository.deleteByAccountId(account.getId());

            userRepository.delete(user);
            userRepository.flush();          // usuário sai antes da conta
            accountRepository.delete(account);
        } else {
            userRepository.delete(user);
        }

        return identity;
    }
}
