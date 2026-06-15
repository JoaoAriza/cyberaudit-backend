package com.joao.cyberaudit.repository;

import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.Domain;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface DomainRepository extends JpaRepository<Domain, UUID> {

    List<Domain> findByAccountOrderByCreatedAtDesc(Account account);

    Optional<Domain> findByAccountAndHost(Account account, String host);

    boolean existsByAccountAndHost(Account account, String host);
}
