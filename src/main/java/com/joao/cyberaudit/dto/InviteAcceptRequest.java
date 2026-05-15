package com.joao.cyberaudit.dto;

import lombok.Data;

@Data
public class InviteAcceptRequest {

    private String password;

    private String name;
}