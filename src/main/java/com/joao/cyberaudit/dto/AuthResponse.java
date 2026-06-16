package com.joao.cyberaudit.dto;

import lombok.Data;

import java.util.List;

@Data
public class AuthResponse {
    private String  token;
    private String  tokenType = "Bearer";
    private UserDto user;

    // Campos 2FA (presentes apenas quando o login exige 2FA)
    private boolean      requires2fa   = false;
    private List<String> twoFactorMethods;

    /** Login completo — sem 2FA. */
    public AuthResponse(String token, UserDto user) {
        this.token = token;
        this.user  = user;
    }

    /** Login parcial — 2FA necessário. */
    public AuthResponse(String preAuthToken, List<String> methods) {
        this.token           = preAuthToken;
        this.requires2fa     = true;
        this.twoFactorMethods = methods;
    }
}