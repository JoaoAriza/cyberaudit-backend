package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class OpenRedirectFinding {
    private String parameter;
    private String testedUrl;
    private String redirectedTo;
    private boolean vulnerable;
    private String severity;
}