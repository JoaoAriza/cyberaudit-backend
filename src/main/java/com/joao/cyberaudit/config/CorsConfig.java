package com.joao.cyberaudit.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CorsConfig {

    /**
     * Origens permitidas lidas da variável de ambiente ALLOWED_ORIGINS.
     * Exemplo: ALLOWED_ORIGINS=http://localhost:5173,https://cyberaudit.vercel.app
     * Fallback de desenvolvimento: localhost em qualquer porta.
     */
    @Value("${cors.allowed-origins}")
    private String allowedOriginsRaw;

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        String[] origins = allowedOriginsRaw.split(",");
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                        .allowedOriginPatterns(origins)
                        .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                        .allowedHeaders("*")
                        .exposedHeaders("*")
                        .allowCredentials(false);
            }
        };
    }
}