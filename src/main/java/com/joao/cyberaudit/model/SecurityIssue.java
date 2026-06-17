package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class SecurityIssue {
    private String id;
    private String title;
    private String severity;
    private String impact;
    private String recommendation;
}
