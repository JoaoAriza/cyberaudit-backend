package com.joao.cyberaudit.dto;

import com.joao.cyberaudit.model.Invite;
import com.joao.cyberaudit.model.Role;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
public class InviteDto {

    private UUID id;
    private String name;
    private String email;
    private Role role;
    private String jobTitle;
    private String invitedByName;
    private boolean accepted;
    private boolean expired;
    private LocalDateTime expiresAt;
    private LocalDateTime createdAt;
    private String acceptLink;

    public static InviteDto from(Invite i) {
        InviteDto dto = new InviteDto();
        dto.setId(i.getId());
        dto.setName(i.getName());
        dto.setEmail(i.getEmail());
        dto.setRole(i.getRole());
        dto.setJobTitle(i.getJobTitle());
        dto.setInvitedByName(i.getInvitedBy() != null
                ? i.getInvitedBy().getName() : null);
        dto.setAccepted(i.isAccepted());
        dto.setExpired(i.isExpired());
        dto.setExpiresAt(i.getExpiresAt());
        dto.setCreatedAt(i.getCreatedAt());
        return dto;
    }
}