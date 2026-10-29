package com.joao.cyberaudit.repository;

import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.ApiKey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface ApiKeyRepository extends JpaRepository<ApiKey, UUID> {

    /** Exclusão de conta (LGPD): remove todas as chaves da conta. */
    void deleteByAccount(Account account);

    /** Exclusão de usuário: chaves criadas por ele. */
    void deleteByCreatedBy(com.joao.cyberaudit.model.AppUser createdBy);

    /** Todas as keys da conta (ativas e revogadas), mais recentes primeiro */
    List<ApiKey> findByAccountOrderByCreatedAtDesc(Account account);

    /** Todas as keys ativas da conta (para validação no filtro) */
    List<ApiKey> findByAccountAndRevokedAtIsNull(Account account);

    /**
     * Candidatas ativas pelo prefixo — reduz o que passa pelo BCrypt.
     *
     * Traz o dono da chave e a conta dele na mesma query. O {@code AppUser} vira o
     * principal do request, e o filtro roda fora de qualquer sessão Hibernate: com
     * {@code createdBy} LAZY, o filtro recebia um proxy e o {@code getAuthorities()}
     * estourava {@code LazyInitializationException} — toda API key, válida ou não,
     * dava 401 (BUG-01). A conta vem junto porque os controllers leem
     * {@code user.getAccount()}, igual ao principal do fluxo JWT
     * ({@code AppUserRepository.findByEmailWithAccount}).
     *
     * JOIN (não LEFT) no dono: chave sem {@code createdBy} não tem quem autenticar.
     */
    @Query("SELECT k FROM ApiKey k JOIN FETCH k.createdBy u LEFT JOIN FETCH u.account "
         + "WHERE k.keyPrefix = :keyPrefix AND k.revokedAt IS NULL")
    List<ApiKey> findActiveByKeyPrefixWithOwner(@Param("keyPrefix") String keyPrefix);

    boolean existsByAccountAndName(Account account, String name);
}
