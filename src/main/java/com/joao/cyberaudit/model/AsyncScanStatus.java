package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AsyncScanStatus {

    public enum State {PENDING, RUNNING, DONE, ERROR }

    private String scanId;
    private State state;

    private ScanResult result;

    private String errorMessage;
}
