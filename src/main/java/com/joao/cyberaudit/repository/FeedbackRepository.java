package com.joao.cyberaudit.repository;

import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.Feedback;
import com.joao.cyberaudit.model.FeedbackStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface FeedbackRepository extends JpaRepository<Feedback, UUID> {

    /** Exclusão de conta (LGPD). */
    void deleteByAccount(Account account);

    void deleteByUser(AppUser user);

    List<Feedback> findByReviewedBy(AppUser reviewedBy);

    /** Feedback enviado por um usuário (view "meus feedbacks"). */
    List<Feedback> findByUserOrderByCreatedAtDesc(AppUser user);

    /** Todos os feedbacks de uma conta (triagem do admin, escopo multi-tenant). */
    List<Feedback> findByAccountOrderByCreatedAtDesc(Account account);

    /** Feedbacks de uma conta filtrados por status. */
    List<Feedback> findByAccountAndStatusOrderByCreatedAtDesc(Account account, FeedbackStatus status);

    /** Contador de pendentes (badge no painel admin). */
    long countByAccountAndStatus(Account account, FeedbackStatus status);

    // ── Triagem da plataforma (cross-tenant) ─────────────────────────────────
    // Contestação é sobre achado que o CyberAudit produziu, então quem tria é a
    // equipe da plataforma — e ela precisa enxergar todas as contas. O acesso a
    // estes métodos é restrito por PlatformStaffService no FeedbackService.

    List<Feedback> findAllByOrderByCreatedAtDesc();

    List<Feedback> findByStatusOrderByCreatedAtDesc(FeedbackStatus status);

    long countByStatus(FeedbackStatus status);
}
