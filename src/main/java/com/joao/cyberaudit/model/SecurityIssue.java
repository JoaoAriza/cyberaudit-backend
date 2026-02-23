package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class SecurityIssue {
    private String id;
    private String title;
    private String severity;
    private String impact;
    private String recommendation;
}
