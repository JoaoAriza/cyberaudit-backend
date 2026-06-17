package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter @Setter @AllArgsConstructor @NoArgsConstructor
public class ScoreResult {
    private int score;
    private RiskLevel riskLevel;
    private List<String> notes;
    private List<SecurityIssue> issues;
}
