package com.joao.cyberaudit.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

/**
 * CORS como {@link CorsConfigurationSource}, e não como WebMvcConfigurer.
 *
 * <h2>Por que não no MVC</h2>
 *
 * O preflight (OPTIONS) é uma requisição sem credencial nenhuma — o navegador
 * nunca manda o Authorization nela. Registrado só no MVC, o CORS ficava atrás
 * do Spring Security: o OPTIONS era julgado pelas regras de autorização antes
 * de chegar ao handler de preflight, caía no {@code anyRequest().authenticated()}
 * e voltava 403. O navegador então nem tentava a requisição real, e o front
 * reportava "Network Error" — sem nada aparecer no log como erro de negócio.
 *
 * O detalhe que mascarou o problema: {@code requestMatchers("/auth/**")} não
 * declara método, então cobria o OPTIONS junto e login/registro funcionavam.
 * Todo o resto (scan, histórico, domínios, conta, admin) exigia método explícito
 * ou caía no catch-all, e só quebrava depois de logar.
 *
 * Como bean, o CorsFilter do Spring Security responde o preflight antes da
 * autorização — que é onde essa decisão pertence.
 */
@Configuration
public class CorsConfig {

    /**
     * Origens permitidas lidas da variável de ambiente ALLOWED_ORIGINS.
     * Exemplo: ALLOWED_ORIGINS=http://localhost:5173,https://cyberauditapp.com
     */
    @Value("${cors.allowed-origins}")
    private String allowedOriginsRaw;

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
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

        CorsConfiguration config = new CorsConfiguration();
        // setAllowedOrigins (não ...Patterns): comparação exata, sem curinga.
        config.setAllowedOrigins(origins);
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Api-Key", "Accept"));
        // Nada de exposedHeaders("*") — o browser só precisa ver o que a UI usa.
        config.setExposedHeaders(List.of("Content-Disposition", "Retry-After"));
        config.setAllowCredentials(false);
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
