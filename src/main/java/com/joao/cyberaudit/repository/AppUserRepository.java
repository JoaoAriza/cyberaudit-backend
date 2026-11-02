package com.joao.cyberaudit.repository;

import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface AppUserRepository extends JpaRepository<AppUser, UUID> {

    Optional<AppUser> findByEmail(String email);

    boolean existsByEmail(String email);

    @Query("SELECT u FROM AppUser u LEFT JOIN FETCH u.account WHERE u.email = :email")
    Optional<AppUser> findByEmailWithAccount(@Param("email") String email);

    List<AppUser> findByAccountAndRole(Account account, Role role);

    /** Usuários de uma conta — base da gestão de equipe em /admin/users. */
    List<AppUser> findByAccount(Account account);

    /** Exclusão de conta: quem foi convidado por este usuário (para soltar a FK). */
    List<AppUser> findByInvitedBy(AppUser invitedBy);

    /**
     * Consome um código TOTP: grava a janela dele como a última usada, mas só se for mais
     * nova que a gravada (BUG-04). Comparar e gravar na mesma UPDATE é o que barra dois
     * pedidos simultâneos com o mesmo código — o segundo altera 0 linhas.
     *
     * @return 1 se o código foi consumido agora; 0 se ele (ou um mais novo) já tinha sido usado
     */
    @Modifying
    @Transactional
    @Query("UPDATE AppUser u SET u.totpLastUsedStep = :step WHERE u.id = :id "
            + "AND (u.totpLastUsedStep IS NULL OR u.totpLastUsedStep < :step)")
    int consumeTotpStep(@Param("id") UUID id, @Param("step") long step);
}