package com.joao.cyberaudit.repository;

import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

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
}