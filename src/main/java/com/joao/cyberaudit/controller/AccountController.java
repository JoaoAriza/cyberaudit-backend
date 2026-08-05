package com.joao.cyberaudit.controller;

import com.joao.cyberaudit.dto.BrandingDto;
import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.AccountType;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.Role;
import com.joao.cyberaudit.repository.AccountRepository;
import com.joao.cyberaudit.service.BrandLogoValidator;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/account")
public class AccountController {

    private final AccountRepository accountRepository;

    public AccountController(AccountRepository accountRepository) {
        this.accountRepository = accountRepository;
    }

    // ── GET /account/branding ─────────────────────────────────────────────────

    /**
     * Retorna as configurações de branding da conta.
     * Acessível a qualquer membro autenticado da conta.
     */
    @GetMapping("/branding")
    public BrandingDto getBranding(@AuthenticationPrincipal AppUser user) {
        checkCompany(user);
        return BrandingDto.from(user.getAccount());
    }

    // ── PUT /account/branding ─────────────────────────────────────────────────

    /**
     * Salva as configurações de branding.
     * Restrito a OWNER e ADMIN.
     *
     * Body: { brandLogoBase64, brandColor, brandReportName }
     * Qualquer campo pode ser null para limpar.
     */
    @PutMapping("/branding")
    public ResponseEntity<BrandingDto> saveBranding(
            @RequestBody BrandingDto dto,
            @AuthenticationPrincipal AppUser user) {

        checkOwnerOrAdmin(user);

        // Valida o logo de verdade: tamanho, formato (PNG/JPEG por assinatura) e
        // DIMENSÕES. A checagem antiga só media a string base64, o que deixava passar
        // bomba de descompressão — um PNG de poucos KB declarando 50000x50000 px
        // estoura a heap quando o PDFBox for desenhar o relatório.
        var logo = BrandLogoValidator.validate(dto.getBrandLogoBase64());
        if (!logo.valid()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, logo.reason());
        }

        // Valida formato hex da cor
        if (dto.getBrandColor() != null
                && !dto.getBrandColor().matches("^#[0-9A-Fa-f]{6}$")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Cor inválida. Use formato hex (#RRGGBB).");
        }

        // Nome do relatório vai para o cabeçalho do PDF e para o banco — sem teto,
        // era string ilimitada em ambos.
        if (dto.getBrandReportName() != null && dto.getBrandReportName().strip().length() > 120) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Nome do relatório muito longo. Máximo 120 caracteres.");
        }

        Account account = user.getAccount();
        account.setBrandLogoBase64(dto.getBrandLogoBase64());
        account.setBrandColor(dto.getBrandColor());
        account.setBrandReportName(dto.getBrandReportName() != null
                ? dto.getBrandReportName().strip() : null);

        accountRepository.save(account);

        return ResponseEntity.ok(BrandingDto.from(account));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void checkCompany(AppUser user) {
        if (user.getAccount().getType() != AccountType.COMPANY
                && !isOwnerOrAdmin(user)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "Branding disponível apenas para contas Empresa.");
        }
    }

    private void checkOwnerOrAdmin(AppUser user) {
        checkCompany(user);
        if (!isOwnerOrAdmin(user)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "Apenas OWNER e ADMIN podem alterar o branding.");
        }
    }

    private boolean isOwnerOrAdmin(AppUser user) {
        return user.getRole() == Role.OWNER || user.getRole() == Role.ADMIN;
    }
}
