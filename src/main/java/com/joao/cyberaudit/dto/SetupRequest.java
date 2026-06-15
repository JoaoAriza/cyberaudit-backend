package com.joao.cyberaudit.dto;

import com.joao.cyberaudit.model.AccountType;
import lombok.Data;

@Data
public class SetupRequest {

    private String name;
    private String email;
    private String password;

    private AccountType accountType;

    private String companyName;
    private String companyDomain;
    private String companySize;
    /** CNPJ enviado pelo cliente (aceita com ou sem máscara). Obrigatório para accountType=COMPANY. */
    private String cnpj;

    private String profession;
    private String website;

    private String country;
}