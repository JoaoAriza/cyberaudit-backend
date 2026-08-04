package com.joao.cyberaudit.service;

import com.joao.cyberaudit.dto.ApiKeyDto;
import com.joao.cyberaudit.model.*;
import com.joao.cyberaudit.repository.ApiKeyRepository;
import org.springframework.http.HttpStatus;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Gestão de API Keys para acesso programático / CI-CD.
 *
 * Formato da chave: ca_<32 hex chars> (total 35 chars)
 * Só o hash BCrypt é persistido. A chave completa é retornada apenas na criação.
 * Validação usa keyPrefix para filtrar candidatos antes de verificar o hash.
 */
@Service
public class ApiKeyService {

    private static final String PREFIX = "ca_";
    private static final int    MAX_KEYS_PER_ACCOUNT = 10;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final ApiKeyRepository apiKeyRepository;
    private final PasswordEncoder  passwordEncoder;
    private final PlanLimitService planLimitService;

    public ApiKeyService(ApiKeyRepository apiKeyRepository,
                         @Qualifier("apiKeyEncoder") PasswordEncoder passwordEncoder,
                         PlanLimitService planLimitService) {
        this.apiKeyRepository = apiKeyRepository;
        this.passwordEncoder  = passwordEncoder;
        this.planLimitService = planLimitService;
    }

    // ── Listagem ──────────────────────────────────────────────────────────────

    public List<ApiKeyDto> list(AppUser user) {
        requireAccount(user);
        return apiKeyRepository.findByAccountOrderByCreatedAtDesc(user.getAccount())
                .stream().map(ApiKeyDto::from).toList();
    }

    // ── Criação ───────────────────────────────────────────────────────────────

    @Transactional
    public ApiKeyDto create(String name, AppUser user) {
        requireAccount(user);
        checkApiKeyAccess(user);

        Account account = user.getAccount();

        // Limite de keys ativas por conta
        long activeCount = apiKeyRepository.findByAccountOrderByCreatedAtDesc(account)
                .stream().filter(ApiKey::isActive).count();
        if (activeCount >= MAX_KEYS_PER_ACCOUNT) {
            throw new ResponseStatusException(HttpStatus.PAYMENT_REQUIRED,
                    "Limite de " + MAX_KEYS_PER_ACCOUNT + " API keys ativas atingido.");
        }

        if (name == null || name.isBlank() || name.length() > 100) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Nome da API key inválido (máx. 100 caracteres).");
        }

        if (apiKeyRepository.existsByAccountAndName(account, name.trim())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Já existe uma API key com este nome.");
        }

        // Gera chave
        byte[] raw = new byte[16];
        RANDOM.nextBytes(raw);
        String hex      = HexFormat.of().formatHex(raw); // 32 hex chars
        String plainKey = PREFIX + hex;                  // ca_<32>
        String keyPrefix = plainKey.substring(0, Math.min(11, plainKey.length())); // "ca_" + 8 chars

        ApiKey key = ApiKey.builder()
                .name(name.trim())
                .keyPrefix(keyPrefix)
                .keyHash(passwordEncoder.encode(plainKey))
                .account(account)
                .createdBy(user)
                .createdAt(LocalDateTime.now())
                .build();

        ApiKey saved = apiKeyRepository.save(key);

        ApiKeyDto dto = ApiKeyDto.from(saved);
        dto.setPlainKey(plainKey); // único momento em que a chave completa é retornada
        return dto;
    }

    // ── Revogação ─────────────────────────────────────────────────────────────

    @Transactional
    public void revoke(UUID keyId, AppUser user) {
        requireAccount(user);
        ApiKey key = apiKeyRepository.findById(keyId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "API key não encontrada."));

        if (!key.getAccount().getId().equals(user.getAccount().getId())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Sem permissão para esta API key.");
        }

        if (key.getRevokedAt() != null) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "API key já revogada.");
        }

        key.setRevokedAt(LocalDateTime.now());
        apiKeyRepository.save(key);
    }

    // ── Validação (usado pelo ApiKeyAuthFilter) ───────────────────────────────

    /**
     * Valida uma API key e retorna o AppUser dono dela.
     * Usa keyPrefix para filtrar candidatos antes do BCrypt (evita full-table scan com hashes).
     *
     * @return Optional vazio se a key for inválida, expirada ou revogada
     */
    public Optional<AppUser> validate(String rawKey) {
        if (rawKey == null || !rawKey.startsWith(PREFIX) || rawKey.length() < 11) {
            return Optional.empty();
        }
        String prefix = rawKey.substring(0, Math.min(11, rawKey.length()));

        List<ApiKey> candidates = apiKeyRepository.findByKeyPrefixAndRevokedAtIsNull(prefix);
        for (ApiKey k : candidates) {
            if (!k.isActive()) continue;
            if (passwordEncoder.matches(rawKey, k.getKeyHash())) {
                // Atualiza lastUsedAt sem bloquear a thread atual
                k.setLastUsedAt(LocalDateTime.now());
                apiKeyRepository.save(k);
                return Optional.of(k.getCreatedBy());
            }
        }
        return Optional.empty();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void requireAccount(AppUser user) {
        if (user == null || user.getAccount() == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Usuário sem conta associada.");
        }
    }

    /**
     * API Keys disponíveis para: OWNER/ADMIN, COMPANY (qualquer plano), PRO INDIVIDUAL.
     * FREE INDIVIDUAL → bloqueado.
     */
    private void checkApiKeyAccess(AppUser user) {
        if (user.getRole() == Role.OWNER || user.getRole() == Role.ADMIN) return;
        Account account = user.getAccount();
        if (account.getType() == AccountType.COMPANY) return;
        Plan plan = planLimitService.effectivePlan(account);
        if (plan == Plan.FREE) {
            throw new ResponseStatusException(HttpStatus.PAYMENT_REQUIRED,
                    "API Keys requerem plano PRO ou conta Empresa.");
        }
    }
}
