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
public class SourceMapFinding {

    /**
     * Categoria do finding:
     * SOURCE_MAP_HEADER  — header SourceMap/X-SourceMap presente em resposta JS
     * SOURCE_MAP_FILE    — arquivo .map acessível publicamente
     * ACTUATOR           — endpoint Spring Boot Actuator exposto
     * DEBUG_ENDPOINT     — endpoint de debug/profiler/console exposto
     */
    private String type;

    /**
     * URL completa acessível.
     */
    private String url;

    /**
     * Trecho da resposta que confirmou a exposição (max 120 chars).
     */
    private String evidence;

    /**
     * HIGH  — source maps, actuator/env, actuator/beans, actuator/heapdump
     * MEDIUM — debug endpoints, actuator/info, actuator/mappings
     * LOW   — actuator/health (geralmente público por design)
     */
    private String severity;
}
