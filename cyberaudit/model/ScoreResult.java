package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;

@Data
@AllArgsConstructor
public class ScoreResult {

    private int score;
    private RiskLevel riskLevel;
    private List<String> notes;
    private List<SecurityIssue> issues;
}
