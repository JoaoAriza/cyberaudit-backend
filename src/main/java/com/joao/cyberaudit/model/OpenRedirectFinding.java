package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class OpenRedirectFinding {
    private String parameter;
    private String testedUrl;
    private String redirectedTo;
    private boolean vulnerable;
    private String severity;
}