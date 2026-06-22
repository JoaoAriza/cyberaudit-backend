package com.joao.cyberaudit.dto;

import com.joao.cyberaudit.model.AccountType;
import lombok.Data;

/**
 * Payload para auto-registro de novos usuários via POST /auth/register.
 * Cria uma conta nova (plan FREE) com o usuário como OWNER.
 */
@Data
public class RegisterRequest {

    private String name;
    private String email;
    private String password;

    /** INDIVIDUAL (padrão) ou COMPANY. */
    private AccountType accountType = AccountType.INDIVIDUAL;

    // ── Campos empresa (obrigatórios se accountType == COMPANY) ───────────────
    private String companyName;
    private String companyDomain;
    private String companySize;
    /** CNPJ (com ou sem máscara). Obrigatório apenas para COMPANY. */
    private String cnpj;

    // ── Campos pessoais ───────────────────────────────────────────────────────
    private String profession;
    private String website;

    private String country;

    /** LGPD — aceite explícito dos Termos de Uso e Política de Privacidade. */
    private boolean termsAccepted;
}
