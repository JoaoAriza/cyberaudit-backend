package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class SensitiveFileFinding {

    /** Caminho verificado: ex "/.env", "/wp-config.php" */
    private String path;

    /** HTTP status retornado: 200 = exposto, 403 = existe mas bloqueado */
    private int statusCode;

    /** "EXPOSED" (200), "PROTECTED" (403), "NOT_FOUND" (404) */
    private String exposure;

    /** Trecho do conteúdo se exposto — primeiros 100 chars */
    private String contentPreview;

    /** Severidade: "CRITICAL", "HIGH", "MEDIUM" */
    private String severity;
}