package com.joao.cyberaudit.controller;

import com.joao.cyberaudit.exception.DomainBlockedException;
import com.joao.cyberaudit.exception.OwnershipNotVerifiedException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(DomainBlockedException.class)
    public ResponseEntity<Map<String, Object>> handleBlocked(DomainBlockedException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                "error",     "DOMAIN_BLOCKED",
                "message",   ex.getMessage(),
                "timestamp", LocalDateTime.now().toString()
        ));
    }

    @ExceptionHandler(OwnershipNotVerifiedException.class)
    public ResponseEntity<Map<String, Object>> handleOwnership(
            OwnershipNotVerifiedException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                "error",         "OWNERSHIP_REQUIRED",
                "message",       ex.getMessage(),
                "passiveResult", ex.getPassiveResult(),
                "timestamp",     LocalDateTime.now().toString()
        ));
    }
}