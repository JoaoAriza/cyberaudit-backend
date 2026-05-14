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
}