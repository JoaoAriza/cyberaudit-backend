package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter @Setter @AllArgsConstructor @NoArgsConstructor
public class SSLInfo {
    private boolean https;
    private boolean valid;
    private String expirationDate;
    private long daysRemaining;
    private String message;

    /**
     * Vida útil TOTAL do certificado em dias (notAfter − notBefore).
     *
     * Existe para o score julgar a expiração em proporção, não em dias absolutos:
     * 30 dias restantes num certificado de 90 é renovação normal; num de 398 é
     * sinal de que a renovação manual está atrasando. 0 = desconhecido (scan
     * antigo, gravado antes deste campo existir).
     */
    private long totalValidityDays;

    /** Construtor legado, sem a vida útil total — mantém scans antigos desserializáveis. */
    public SSLInfo(boolean https, boolean valid, String expirationDate,
                   long daysRemaining, String message) {
        this(https, valid, expirationDate, daysRemaining, message, 0L);
    }
}
