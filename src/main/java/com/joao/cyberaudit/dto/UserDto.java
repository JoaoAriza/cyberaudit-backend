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

    public static UserDto from(AppUser u) {
        UserDto dto = new UserDto();
        dto.setId(u.getId());
        dto.setName(u.getName());
        dto.setEmail(u.getEmail());
        dto.setRole(u.getRole());
        dto.setJobTitle(u.getJobTitle());
        dto.setCountry(u.getCountry());
        dto.setAccount(AccountDto.from(u.getAccount()));
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

        if (u.getAccount() != null) {
            int remaining = planLimitService.getRemainingScans(u);
            dto.setRemainingScans(remaining < 0 ? null : remaining);
            dto.setDailyLimit(effectivePlan.isUnlimited() ? null : effectivePlan.dailyScanLimit);
        }
        return dto;
    }
}