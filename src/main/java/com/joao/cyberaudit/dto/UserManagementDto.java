package com.joao.cyberaudit.dto;

import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.Role;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
public class UserManagementDto {

    private UUID id;
    private String name;
    private String email;
    private Role role;
    private String jobTitle;
    private boolean active;
    private LocalDateTime createdAt;
    private String invitedByName;
    private AccountDto account;

    public static UserManagementDto from(AppUser u) {
        UserManagementDto dto = new UserManagementDto();
        dto.setId(u.getId());
        dto.setName(u.getName());
        dto.setEmail(u.getEmail());
        dto.setRole(u.getRole());
        dto.setJobTitle(u.getJobTitle());
        dto.setActive(u.isActive());
        dto.setCreatedAt(u.getCreatedAt());
        dto.setInvitedByName(u.getInvitedBy() != null
                ? u.getInvitedBy().getName() : "Sistema");
        dto.setAccount(AccountDto.from(u.getAccount()));
        return dto;
    }
}