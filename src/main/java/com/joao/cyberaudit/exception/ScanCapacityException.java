package com.joao.cyberaudit.exception;

/**
 * Não há slot livre para executar mais um scan. Mapeada para HTTP 503 —
 * é uma condição transitória de capacidade, não um erro do cliente.
 */
public class ScanCapacityException extends RuntimeException {
    public ScanCapacityException(String message) {
        super(message);
    }
}
