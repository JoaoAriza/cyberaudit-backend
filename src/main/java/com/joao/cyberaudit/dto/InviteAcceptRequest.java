package com.joao.cyberaudit.dto;

import lombok.Data;

@Data
public class InviteAcceptRequest {

    private String password;
    private String name;

    /** LGPD — aceite explícito dos Termos de Uso e Política de Privacidade. */
    private boolean termsAccepted;
}