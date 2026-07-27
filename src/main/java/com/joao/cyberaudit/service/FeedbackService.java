package com.joao.cyberaudit.service;

import com.joao.cyberaudit.dto.FeedbackDto;
import com.joao.cyberaudit.dto.FeedbackReplyRequest;
import com.joao.cyberaudit.dto.FeedbackRequest;
import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.Feedback;
import com.joao.cyberaudit.model.FeedbackStatus;
import com.joao.cyberaudit.model.Role;
import com.joao.cyberaudit.repository.AppUserRepository;
import com.joao.cyberaudit.repository.FeedbackRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Regras de negócio dos feedbacks (contestação de achados) — submissão pelo
 * cliente, triagem pelo admin (escopo multi-tenant por conta) e notificação.
 */
@Service
public class FeedbackService {

    private static final int MAX_MESSAGE_LEN = 4000;

    private final FeedbackRepository feedbackRepository;
    private final AppUserRepository userRepository;
    private final EmailService emailService;

    /** Caixa opcional da plataforma que recebe cópia de TODO feedback (cross-tenant). */
    @Value("${feedback.notify.email:}")
    private String platformNotifyEmail;

    public FeedbackService(FeedbackRepository feedbackRepository,
                           AppUserRepository userRepository,
                           EmailService emailService) {
        this.feedbackRepository = feedbackRepository;
        this.userRepository     = userRepository;
        this.emailService       = emailService;
    }

    // ── Cliente ─────────────────────────────────────────────────────────────

    @Transactional
    public FeedbackDto submit(AppUser submitter, FeedbackRequest req) {
        if (req.getHost() == null || req.getHost().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Host é obrigatório.");
        }
        if (req.getMessage() == null || req.getMessage().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Mensagem é obrigatória.");
        }

        String message = req.getMessage().trim();
        if (message.length() > MAX_MESSAGE_LEN) {
            message = message.substring(0, MAX_MESSAGE_LEN);
        }

        Feedback fb = Feedback.builder()
                .scanId(req.getScanId())
                .host(req.getHost().trim())
                .module(trimOrNull(req.getModule()))
                .findingLabel(trimOrNull(req.getFindingLabel()))
                .message(message)
                .status(FeedbackStatus.OPEN)
                .user(submitter)
                .account(submitter.getAccount())
                .createdAt(LocalDateTime.now())
                .build();

        fb = feedbackRepository.save(fb);

        notifyAdmins(fb, submitter);

        return FeedbackDto.from(fb);
    }

    @Transactional(readOnly = true)
    public List<FeedbackDto> listMine(AppUser user) {
        return feedbackRepository.findByUserOrderByCreatedAtDesc(user)
                .stream().map(FeedbackDto::from).toList();
    }

    // ── Admin (escopo: própria conta) ─────────────────────────────────────────

    @Transactional(readOnly = true)
    public List<FeedbackDto> listForAdmin(AppUser admin, FeedbackStatus status) {
        Account account = admin.getAccount();
        if (account == null) return List.of();
        List<Feedback> list = (status != null)
                ? feedbackRepository.findByAccountAndStatusOrderByCreatedAtDesc(account, status)
                : feedbackRepository.findByAccountOrderByCreatedAtDesc(account);
        return list.stream().map(FeedbackDto::from).toList();
    }

    @Transactional(readOnly = true)
    public long countPending(AppUser admin) {
        Account account = admin.getAccount();
        if (account == null) return 0;
        return feedbackRepository.countByAccountAndStatus(account, FeedbackStatus.OPEN);
    }

    @Transactional
    public FeedbackDto reply(AppUser admin, UUID id, FeedbackReplyRequest req) {
        Feedback fb = feedbackRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Feedback não encontrado."));

        // Escopo multi-tenant: o admin só age sobre feedback da própria conta.
        if (fb.getAccount() == null || admin.getAccount() == null
                || !fb.getAccount().getId().equals(admin.getAccount().getId())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Feedback pertence a outra conta.");
        }

        if (req.getAdminResponse() != null && !req.getAdminResponse().isBlank()) {
            fb.setAdminResponse(req.getAdminResponse().trim());
        }
        if (req.getStatus() != null) {
            fb.setStatus(req.getStatus());
            if (req.getStatus() == FeedbackStatus.RESOLVED && fb.getResolvedAt() == null) {
                fb.setResolvedAt(LocalDateTime.now());
            }
        }
        fb.setReviewedBy(admin);
        fb.setUpdatedAt(LocalDateTime.now());
        fb = feedbackRepository.save(fb);

        return FeedbackDto.from(fb);
    }

    // ── Interno ────────────────────────────────────────────────────────────────

    private void notifyAdmins(Feedback fb, AppUser submitter) {
        try {
            Set<String> recipients = new LinkedHashSet<>();
            Account account = submitter.getAccount();
            if (account != null) {
                List<AppUser> admins = new ArrayList<>();
                admins.addAll(userRepository.findByAccountAndRole(account, Role.OWNER));
                admins.addAll(userRepository.findByAccountAndRole(account, Role.ADMIN));
                for (AppUser a : admins) {
                    // não notifica o próprio remetente (ex: OWNER individual contestando)
                    if (!a.getId().equals(submitter.getId()) && a.getEmail() != null) {
                        recipients.add(a.getEmail());
                    }
                }
            }
            if (platformNotifyEmail != null && !platformNotifyEmail.isBlank()) {
                recipients.add(platformNotifyEmail.trim());
            }
            for (String to : recipients) {
                emailService.sendFeedbackNotification(to, submitter.getName(), fb);
            }
        } catch (Exception ignored) {
            // a notificação nunca deve quebrar a submissão do feedback
        }
    }

    private static String trimOrNull(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }
}
