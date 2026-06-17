package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NoArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ApiDocsExposureFinding {

    /** Caminho acessado: ex "/swagger-ui/index.html", "/v3/api-docs" */
    private String path;

    /**
     * Tipo de documentacao exposta:
     * "SWAGGER_UI"    — interface Swagger UI interativa
     * "OPENAPI_JSON"  — spec OpenAPI/Swagger em JSON (schema completo da API)
     * "OPENAPI_YAML"  — spec OpenAPI em YAML
     * "REDOC"         — interface ReDoc
     * "API_DOCS"      — endpoint generico de documentacao
     */
    private String type;

    /** "HIGH" para specs JSON/YAML (schema completo), "MEDIUM" para UIs */
    private String severity;

    /** Trecho do body que confirmou a deteccao */
    private String evidence;

    /** Descricao legivel do risco */
    private String description;
}
