package com.joao.cyberaudit.dto;

import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.AccountType;
import lombok.Data;

import java.util.UUID;

@Data
public class AccountDto {

    private UUID id;
    private AccountType type;
    private String displayName;
    private String companyName;
    private String country;

    public static AccountDto from(Account a) {
        if (a == null) return null;
        AccountDto dto = new AccountDto();
        dto.setId(a.getId());
        dto.setType(a.getType());
        dto.setDisplayName(a.getDisplayName());
        dto.setCompanyName(a.getCompanyName());
        dto.setCountry(a.getCountry());
        return dto;
    }
}