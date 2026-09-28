package com.joao.cyberaudit.exception;

import com.joao.cyberaudit.model.ScanResult;
import lombok.Getter;

@Getter
public class OwnershipNotVerifiedException extends RuntimeException {

    private final ScanResult passiveResult;
    private final String host;

    public OwnershipNotVerifiedException(ScanResult passiveResult, String host, String message) {
        super(message);
        this.passiveResult = passiveResult;
        this.host = host;
    }
}