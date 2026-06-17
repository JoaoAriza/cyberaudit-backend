package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter @Setter @AllArgsConstructor @NoArgsConstructor
public class SSLInfo {
    private boolean https;
    private boolean valid;
    private String expirationDate;
    private long daysRemaining;
    private String message;
}
