package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class HttpMethodFinding {

    /** Método testado: "TRACE", "PUT", "DELETE", etc. */
    private String method;

    /** HTTP status retornado */
    private int statusCode;

    /** true se o método foi aceito pelo servidor */
    private boolean enabled;

    /** Severidade do risco */
    private String severity;

    /** Descrição do risco específico desse método */
    private String risk;
}