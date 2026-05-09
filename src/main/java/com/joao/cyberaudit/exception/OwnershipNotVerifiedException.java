package com.joao.cyberaudit.exception;

import com.joao.cyberaudit.model.ScanResult;
import lombok.Getter;

@Getter
public class OwnershipNotVerifiedException extends RuntimeException {

    private final ScanResult passiveResult;

    public OwnershipNotVerifiedException(ScanResult passiveResult, String message) {
        super(message);
        this.passiveResult = passiveResult;
    }
}