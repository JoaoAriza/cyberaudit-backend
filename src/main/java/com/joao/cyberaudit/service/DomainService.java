package com.joao.cyberaudit.service;

import com.joao.cyberaudit.dto.DomainDto;
import com.joao.cyberaudit.dto.SubdomainInfo;
import com.joao.cyberaudit.model.AccountType;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.Domain;
import com.joao.cyberaudit.model.Role;
import com.joao.cyberaudit.repository.DomainRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Service
public class DomainService {

    private final DomainRepository              domainRepository;
    private final DomainProtectionService       domainProtectionService;
    private final SubdomainEnumerationService   subdomainEnumerationService;

    public DomainService(DomainRepository domainRepository,
                         DomainProtectionService domainProtectionService,
                         SubdomainEnumerationService subdomainEnumerationService) {
        this.domainRepository             = domainRepository;
        this.domainProtectionService      = domainProtectionService;
        this.subdomainEnumerationService  = subdomainEnumerationService;
    }

    // ── Listagem ──────────────────────────────────────────────────────────────

    public List<DomainDto> list(AppUser user) {
        requireAccount(user);
        return domainRepository.findByAccountOrderByCreatedAtDesc(user.getAccount())
                .stream()
                .map(d -> DomainDto.from(d, domainProtectionService.generateVerificationToken(d.getHost())))
                .toList();
    }

    // ── Cadastro ──────────────────────────────────────────────────────────────

    @Transactional
    public DomainDto add(String rawHost, AppUser user) {
        requireAccount(user);

        String host = normalize(rawHost);

        if (domainRepository.existsByAccountAndHost(user.getAccount(), host)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Domínio já cadastrado nesta conta.");
        }

        Domain domain = Domain.builder()
                .account(user.getAccount())
                .host(host)
                .verified(false)
                .createdAt(LocalDateTime.now())
                .build();

        Domain saved = domainRepository.save(domain);
        return DomainDto.from(saved, domainProtectionService.generateVerificationToken(host));
    }

    // ── Remoção ───────────────────────────────────────────────────────────────

    @Transactional
    public void remove(UUID domainId, AppUser user) {
        Domain domain = getOwned(domainId, user);
        domainRepository.delete(domain);
    }

    // ── Verificação de propriedade ────────────────────────────────────────────

    @Transactional
    public DomainDto verify(UUID domainId, AppUser user) {
        Domain domain = getOwned(domainId, user);

        boolean ok = domainProtectionService.isOwnershipVerified(domain.getHost());
        if (!ok) {
            throw new ResponseStatusException(HttpStatus.EXPECTATION_FAILED,
                    "Verificação falhou. Certifique-se de que o arquivo /.well-known/cyberaudit.txt "
                    + "está acessível com o token correto e tente novamente.");
        }

        domain.setVerified(true);
        domain.setVerifiedAt(LocalDateTime.now());
        return DomainDto.from(domainRepository.save(domain),
                domainProtectionService.generateVerificationToken(domain.getHost()));
    }

    // ── Enumeração de subdomínios (EMPRESA) ───────────────────────────────────

    public List<SubdomainInfo> enumerate(UUID domainId, AppUser user) {
        requireAccount(user);

        // Apenas COMPANY ou OWNER/ADMIN
        boolean isAdmin = user.getRole() == Role.OWNER || user.getRole() == Role.ADMIN;
        boolean isCompany = user.getAccount().getType() == AccountType.COMPANY;
        if (!isAdmin && !isCompany) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "Enumeração de subdomínios está disponível apenas para contas Empresa.");
        }

        Domain domain = getOwned(domainId, user);

        if (!domain.isVerified()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Verifique a propriedade do domínio antes de enumerar subdomínios.");
        }

        return subdomainEnumerationService.enumerate(domain.getHost());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private Domain getOwned(UUID domainId, AppUser user) {
        requireAccount(user);
        Domain domain = domainRepository.findById(domainId)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Domínio não encontrado."));
        if (!domain.getAccount().getId().equals(user.getAccount().getId())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "Sem permissão para este domínio.");
        }
        return domain;
    }

    private void requireAccount(AppUser user) {
        if (user == null || user.getAccount() == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "Usuário sem conta associada.");
        }
    }

    /** Remove protocolo, trailing slash e path — mantém só o hostname. */
    private String normalize(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Host não pode ser vazio.");
        }
        return raw.trim()
                  .replaceFirst("^https?://", "")
                  .split("/")[0]
                  .toLowerCase();
    }
}
