package com.joao.cyberaudit.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Contrato do CORS.
 *
 * O que derrubou a produção não foi o conteúdo desta configuração — era ela
 * estar registrada no MVC, atrás do Spring Security, onde o preflight já tinha
 * levado 403. Isso é ordem de filtro e só um teste que suba a cadeia inteira
 * pega; aqui trava o que dá para travar em unidade: o Authorization precisa ser
 * aceito (é ele que obriga o preflight a existir) e o curinga precisa continuar
 * barrado no boot.
 */
class CorsConfigTest {

    private CorsConfiguration configComOrigens(String raw) {
        CorsConfig cors = new CorsConfig();
        ReflectionTestUtils.setField(cors, "allowedOriginsRaw", raw);

        var source = (UrlBasedCorsConfigurationSource) cors.corsConfigurationSource();
        CorsConfiguration config = source.getCorsConfigurations().get("/**");

        assertNotNull(config, "a configuração precisa valer para todas as rotas");
        return config;
    }

    @Test
    @DisplayName("Authorization é aceito — sem ele todo endpoint logado falha no preflight")
    void permiteHeaderAuthorization() {
        var config = configComOrigens("https://cyberauditapp.com");

        assertTrue(config.getAllowedHeaders().contains("Authorization"));
    }

    @Test
    @DisplayName("OPTIONS está entre os métodos permitidos")
    void permiteOptions() {
        var config = configComOrigens("https://cyberauditapp.com");

        assertTrue(config.getAllowedMethods().contains("OPTIONS"));
    }

    @Test
    @DisplayName("origens são exatas, sem curinga, e aceitam lista com espaços")
    void origensExatas() {
        var config = configComOrigens(" https://cyberauditapp.com , https://www.cyberauditapp.com ");

        assertEquals(
                List.of("https://cyberauditapp.com", "https://www.cyberauditapp.com"),
                config.getAllowedOrigins());
        assertFalse(config.getAllowedOrigins().contains("*"));
    }

    @Test
    @DisplayName("só expõe os headers que a UI realmente lê")
    void exposedHeaders() {
        var config = configComOrigens("https://cyberauditapp.com");

        assertEquals(List.of("Content-Disposition", "Retry-After"), config.getExposedHeaders());
    }

    @Test
    @DisplayName("credenciais seguem desligadas — a auth é por Bearer, não cookie")
    void semCredenciais() {
        var config = configComOrigens("https://cyberauditapp.com");

        assertFalse(Boolean.TRUE.equals(config.getAllowCredentials()));
    }

    @Test
    @DisplayName("curinga derruba o boot em vez de abrir a API para a internet inteira")
    void curingaFalhaNoBoot() {
        assertThrows(IllegalStateException.class, () -> configComOrigens("*"));
        assertThrows(IllegalStateException.class,
                () -> configComOrigens("https://cyberauditapp.com,*"));
    }

    @Test
    @DisplayName("lista vazia também derruba o boot")
    void vazioFalhaNoBoot() {
        assertThrows(IllegalStateException.class, () -> configComOrigens(""));
        assertThrows(IllegalStateException.class, () -> configComOrigens("  ,  "));
    }
}
