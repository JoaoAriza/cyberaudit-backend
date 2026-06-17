package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter @Setter @AllArgsConstructor @NoArgsConstructor
public class CookieFinding {
    private String name;
    private boolean httpOnly;
    private boolean secure;
    private String sameSite;
    private String risk;
    private String issues;
}
