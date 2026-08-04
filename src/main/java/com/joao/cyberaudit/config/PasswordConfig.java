package com.joao.cyberaudit.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Separa o PasswordEncoder bean de SecurityConfig para evitar
 * dependência circular com ApiKeyService.
 */
@Configuration
public class PasswordConfig {

    /**
     * Senhas de usuário — custo 12 (padrão do Spring é 10). Hashes antigos
     * continuam validando: o BCrypt carrega o custo no próprio hash, só as
     * senhas novas usam 12.
     */
    @Bean
    @Primary
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    /**
     * API keys — custo 10, deliberadamente menor que o das senhas.
     *
     * O hash de API key é verificado a CADA requisição autenticada por
     * X-Api-Key; custo 12 colocaria ~250 ms de CPU em cada chamada de CI/CD.
     * O custo alto existe para proteger senhas humanas (baixa entropia, sujeitas
     * a dicionário) — uma API key é token aleatório de alta entropia, onde
     * derivação lenta não compra nada.
     */
    @Bean("apiKeyEncoder")
    public PasswordEncoder apiKeyEncoder() {
        return new BCryptPasswordEncoder(10);
    }
}
