package com.joao.cyberaudit.exception;

public class DomainBlockedException extends RuntimeException {
    public DomainBlockedException(String message) {
        super(message);
    }
}