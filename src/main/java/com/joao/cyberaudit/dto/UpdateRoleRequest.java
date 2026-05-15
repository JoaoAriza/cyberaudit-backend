package com.joao.cyberaudit.dto;

import com.joao.cyberaudit.model.Role;
import lombok.Data;

@Data
public class UpdateRoleRequest {
    private Role role;
}