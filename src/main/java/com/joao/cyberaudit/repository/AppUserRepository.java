package com.joao.cyberaudit.repository;

import com.joao.cyberaudit.model.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface AppUserRepository extends JpaRepository<AppUser, UUID> {

    Optional<AppUser> findByEmail(String email);

    boolean existsByEmail(String email);

    @Query("SELECT u FROM AppUser u LEFT JOIN FETCH u.account WHERE u.email = :email")
    Optional<AppUser> findByEmailWithAccount(@Param("email") String email);
}