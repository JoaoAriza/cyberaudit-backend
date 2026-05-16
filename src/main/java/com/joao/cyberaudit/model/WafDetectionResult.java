package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class WafDetectionResult {

    private boolean detected;
    private String provider;
    private String confidence;
    private String evidence;
    private String probeResponse;
    private String summary;
}