package com.joao.cyberaudit.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.Arrays;
import java.util.List;

@Configuration
public class CorsConfig {

    /**
     * Origens permitidas lidas da variável de ambiente ALLOWED_ORIGINS.
     * Exemplo: ALLOWED_ORIGINS=http://localhost:5173,https://cyberaudit.vercel.app
     */
    @Value("${cors.allowed-origins}")
    private String allowedOriginsRaw;

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        List<String> origins = Arrays.stream(allowedOriginsRaw.split(","))
                .map(String::trim)
                .filter(o -> !o.isEmpty())
                .toList();

        // Falha no boot em vez de subir com CORS liberado para a internet inteira.
        // allowCredentials está false hoje (a auth é por Bearer, não cookie), o que
        // torna "*" menos perigoso — mas um "*" configurado sem querer viraria uma
        // porta escancarada no dia em que credenciais forem ligadas.
        if (origins.isEmpty() || origins.contains("*")) {
            throw new IllegalStateException(
                    "cors.allowed-origins inválido: defina ALLOWED_ORIGINS com as origens "
                            + "reais do frontend (curinga '*' não é aceito).");
        }

        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                        // allowedOrigins (não ...Patterns): comparação exata, sem curinga.
                        .allowedOrigins(origins.toArray(String[]::new))
                        .allowedMethods("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
                        .allowedHeaders("Authorization", "Content-Type", "X-Api-Key", "Accept")
                        // Nada de exposedHeaders("*") — o browser só precisa ver o que a UI usa.
                        .exposedHeaders("Content-Disposition", "Retry-After")
                        .allowCredentials(false)
                        .maxAge(3600);
            }
        };
    }
}
