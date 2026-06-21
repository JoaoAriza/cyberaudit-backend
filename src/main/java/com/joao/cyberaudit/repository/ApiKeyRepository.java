package com.joao.cyberaudit.repository;

import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.ApiKey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface ApiKeyRepository extends JpaRepository<ApiKey, UUID> {

    /** Todas as keys da conta (ativas e revogadas), mais recentes primeiro */
    List<ApiKey> findByAccountOrderByCreatedAtDesc(Account account);

    /** Todas as keys ativas da conta (para validação no filtro) */
    List<ApiKey> findByAccountAndRevokedAtIsNull(Account account);

    /** Conta com base no prefixo — reduz candidates para verificação de hash */
    List<ApiKey> findByKeyPrefixAndRevokedAtIsNull(String keyPrefix);

    boolean existsByAccountAndName(Account account, String name);
}
