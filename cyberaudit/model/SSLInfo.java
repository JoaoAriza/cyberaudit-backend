package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class SSLInfo {

    private boolean https;
    private boolean valid;
    private String expirationDate;
    private long daysRemaining;
    private String message;
}
