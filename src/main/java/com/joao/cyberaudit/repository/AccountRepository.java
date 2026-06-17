package com.joao.cyberaudit.repository;

import com.joao.cyberaudit.model.Account;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface AccountRepository extends JpaRepository<Account, UUID> {
    Optional<Account> findByPublicStatusToken(String publicStatusToken);
}