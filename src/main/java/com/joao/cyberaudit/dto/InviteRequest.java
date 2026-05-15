package com.joao.cyberaudit.dto;

import com.joao.cyberaudit.model.Role;
import lombok.Data;

@Data
public class InviteRequest {

    private String name;

    private String email;

    private Role role;

    private String jobTitle;
}