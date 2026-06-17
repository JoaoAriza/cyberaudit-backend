package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NoArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class JwtSecurityFinding {

    /** Nome do cookie que contem o JWT, ou "Authorization" se veio do header */
    private String source;

    /**
     * Algoritmo declarado no header do JWT (campo "alg").
     * "none"         — CRITICAL: sem assinatura, token pode ser forjado
     * "HS256/384/512" — simetrico: seguranca depende da forca do segredo
     * "RS256/ES256"  — assimetrico: algoritmo seguro
     * "UNKNOWN"      — header invalido ou nao foi possivel decodificar
     */
    private String algorithm;

    /** Token possui claim "exp" (expiracao) */
    private boolean hasExpiry;

    /**
     * Token ja esta expirado com base no claim "exp" vs hora atual.
     * Um token expirado sendo enviado pelo servidor indica problema de gerenciamento.
     */
    private boolean expired;

    /** Token possui claim "iss" (issuer) */
    private boolean hasIssuer;

    /** Token possui claim "aud" (audience) */
    private boolean hasAudience;

    /** Lista de problemas especificos encontrados */
    private List<String> issues;

    /** "CRITICAL", "HIGH", "MEDIUM", "LOW" */
    private String severity;

    /**
     * Trecho do header decodificado para evidencia (nunca inclui o payload completo
     * nem a assinatura — apenas o header JSON e claims nao-sensiveis do payload).
     */
    private String evidence;
}
