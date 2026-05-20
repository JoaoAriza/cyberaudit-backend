package com.joao.cyberaudit.controller;

import com.joao.cyberaudit.exception.DomainBlockedException;
import com.joao.cyberaudit.exception.GuestDailyLimitException;
import com.joao.cyberaudit.exception.OwnershipNotVerifiedException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;

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
                "error",     "OWNERSHIP_REQUIRED",
                "message",   ex.getMessage(),
                "timestamp", LocalDateTime.now().toString()
        ));
    }

    @ExceptionHandler(GuestDailyLimitException.class)
    public ResponseEntity<Map<String, Object>> handleGuestLimit(GuestDailyLimitException ex) {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(Map.of(
                "error",          "DAILY_LIMIT_REACHED",
                "message",        "Limite de " + ex.getDailyLimit() + " scans diários atingido.",
                "remainingScans", 0,
                "resetsAt",       ex.getResetsAt().toString(),
                "upgrade",        "Para acesso ilimitado, solicite um convite ao administrador."
        ));
    }

    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<Map<String, Object>> handleResponseStatus(
            ResponseStatusException ex) {
        return ResponseEntity.status(ex.getStatusCode()).body(Map.of(
                "error",   ex.getStatusCode().toString(),
                "message", ex.getReason() != null ? ex.getReason() : "Erro interno"
        ));
    }

    @ExceptionHandler(java.net.UnknownHostException.class)
    public ResponseEntity<Map<String, Object>> handleUnknownHost(java.net.UnknownHostException ex) {
        return ResponseEntity.badRequest().body(Map.of(
                "error",   "UNKNOWN_HOST",
                "message", "Domínio não encontrado: " + ex.getMessage()
        ));
    }

    @ExceptionHandler(java.net.ConnectException.class)
    public ResponseEntity<Map<String, Object>> handleConnectException(java.net.ConnectException ex) {
        return ResponseEntity.badRequest().body(Map.of(
                "error",   "CONNECTION_FAILED",
                "message", "Não foi possível conectar ao host: " + ex.getMessage()
        ));
    }

    @ExceptionHandler(java.net.SocketTimeoutException.class)
    public ResponseEntity<Map<String, Object>> handleTimeout(java.net.SocketTimeoutException ex) {
        return ResponseEntity.badRequest().body(Map.of(
                "error",   "CONNECTION_TIMEOUT",
                "message", "Tempo de conexão esgotado. O host pode estar offline ou inacessível."
        ));
    }
}