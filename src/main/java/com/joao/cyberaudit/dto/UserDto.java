package com.joao.cyberaudit.dto;

import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.Role;
import lombok.Data;

import java.util.UUID;

@Data
public class UserDto {

    private UUID id;
    private String name;
    private String email;
    private Role role;
    private String jobTitle;
    private String country;
    private AccountDto account;

    private Integer remainingScans;
    private Integer dailyLimit;

    // 2FA status (retornado em /auth/me)
    private boolean totpEnabled;
    private boolean emailOtpEnabled;

    /**
     * Equipe da plataforma (PLATFORM_STAFF_EMAILS) — não é o dono da conta.
     * A UI usa isto para mostrar a triagem de contestações só para nós; o
     * backend não confia neste campo, ele revalida em PlatformStaffService.
     */
    private boolean platformStaff;

    public static UserDto from(AppUser u) {
        UserDto dto = new UserDto();
        dto.setId(u.getId());
        dto.setName(u.getName());
        dto.setEmail(u.getEmail());
        dto.setRole(u.getRole());
        dto.setJobTitle(u.getJobTitle());
        dto.setCountry(u.getCountry());
        dto.setAccount(AccountDto.from(u.getAccount()));
        dto.setTotpEnabled(u.isTotpEnabled());
        dto.setEmailOtpEnabled(u.isEmailOtpEnabled());
        return dto;
    }

    /**
     * Variante que popula remainingScans, dailyLimit e limites de plano efetivo via PlanLimitService.
     * Aplica bypass de OWNER/ADMIN (eles recebem os limites do plano ENTERPRISE).
     * Usado nos endpoints de login, setup e /me.
     */
    public static UserDto from(AppUser u, com.joao.cyberaudit.service.PlanLimitService planLimitService) {
        com.joao.cyberaudit.model.Plan effectivePlan = planLimitService.effectivePlan(u);

        // Reconstrói o AccountDto usando o plano efetivo (importante para OWNER/ADMIN)
        UserDto dto = new UserDto();
        dto.setId(u.getId());
        dto.setName(u.getName());
        dto.setEmail(u.getEmail());
        dto.setRole(u.getRole());
        dto.setJobTitle(u.getJobTitle());
        dto.setCountry(u.getCountry());
        dto.setAccount(AccountDto.from(u.getAccount(), effectivePlan));
        dto.setTotpEnabled(u.isTotpEnabled());
        dto.setEmailOtpEnabled(u.isEmailOtpEnabled());
        dto.setPlatformStaff(planLimitService.isPlatformStaff(u));

        if (u.getAccount() != null) {
            int remaining = planLimitService.getRemainingScans(u);
            dto.setRemainingScans(remaining < 0 ? null : remaining);
            dto.setDailyLimit(effectivePlan.isUnlimited() ? null : effectivePlan.dailyScanLimit);
        }
        return dto;
    }
}