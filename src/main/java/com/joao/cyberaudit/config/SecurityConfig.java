package com.joao.cyberaudit.config;

import com.joao.cyberaudit.security.ApiKeyAuthFilter;
import com.joao.cyberaudit.security.JwtAuthFilter;
import com.joao.cyberaudit.security.JwtUtil;
import com.joao.cyberaudit.security.UserDetailsServiceImpl;
import com.joao.cyberaudit.service.ApiKeyService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.config.Customizer;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtUtil               jwtUtil;
    private final UserDetailsServiceImpl userDetailsServiceImpl;
    private final ApiKeyService          apiKeyService;
    private final PasswordEncoder        passwordEncoder;

    public SecurityConfig(JwtUtil jwtUtil,
                          UserDetailsServiceImpl userDetailsServiceImpl,
                          ApiKeyService apiKeyService,
                          PasswordEncoder passwordEncoder) {
        this.jwtUtil               = jwtUtil;
        this.userDetailsServiceImpl = userDetailsServiceImpl;
        this.apiKeyService          = apiKeyService;
        this.passwordEncoder        = passwordEncoder;
    }

    /**
     * Cria o JwtAuthFilter como @Bean sem @Component no filtro.
     * Isso evita que o Spring Boot o registre automaticamente como servlet filter,
     * eliminando o problema de dupla execução com OncePerRequestFilter.
     */
    @Bean
    public JwtAuthFilter jwtAuthFilter() {
        return new JwtAuthFilter(jwtUtil, userDetailsServiceImpl);
    }

    @Bean
    public ApiKeyAuthFilter apiKeyAuthFilter() {
        return new ApiKeyAuthFilter(apiKeyService);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .exceptionHandling(e -> e.authenticationEntryPoint(restAuthenticationEntryPoint()))
                // Sem isto o preflight (OPTIONS, sempre sem credencial) é julgado pelas
                // regras abaixo e volta 403 — o navegador aborta antes da requisição
                // real e o front só enxerga "Network Error". Usa o
                // CorsConfigurationSource de CorsConfig e responde antes da autorização.
                .cors(Customizer.withDefaults())
                .sessionManagement(sm -> sm
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth

                        // ── Públicos sem auth ──────────────────────────────────────
                        .requestMatchers("/auth/**").permitAll()
                        .requestMatchers("/badge/**").permitAll()
                        .requestMatchers("/actuator/health", "/actuator/info").permitAll()

                        // ── Página de status pública (sem auth) ───────────────────
                        .requestMatchers(HttpMethod.GET, "/public/status/**").permitAll()

                        // ── Scan passivo e async: público ──────────────────────────
                        .requestMatchers(HttpMethod.GET,  "/scan").permitAll()
                        .requestMatchers(HttpMethod.POST, "/scan/async").permitAll()
                        .requestMatchers(HttpMethod.GET,  "/scan/async/**").permitAll()
                        .requestMatchers(HttpMethod.GET,  "/scan/report").permitAll()

                        // ── Verify-check público (guests no OwnershipCard) ─────────
                        .requestMatchers(HttpMethod.GET, "/scan/verify-check").permitAll()

                        // ── Webhook do Mercado Pago (público; validado contra a API do MP) ─
                        .requestMatchers(HttpMethod.POST, "/billing/webhook").permitAll()
                        // ── Cardápio de planos: público, é o que o visitante vem ver ─
                        .requestMatchers(HttpMethod.GET, "/billing/plans").permitAll()
                        // ── Assinatura (autenticado) ───────────────────────────────
                        .requestMatchers("/billing/**").authenticated()

                        // ── Scan autenticado ───────────────────────────────────────
                        .requestMatchers(HttpMethod.GET, "/scan/report/pdf").authenticated()
                        .requestMatchers("/scan/verify-token").authenticated()

                        // ── CI/CD gate — autenticado via X-Api-Key ─────────────────
                        .requestMatchers(HttpMethod.GET, "/api-keys/ci").authenticated()

                        // ── API Keys CRUD ──────────────────────────────────────────
                        .requestMatchers("/api-keys/**").authenticated()

                        // ── Histórico ──────────────────────────────────────────────
                        .requestMatchers("/history/**").authenticated()
                        .requestMatchers("/scheduled-scans/**").authenticated()

                        // ── Domínios ───────────────────────────────────────────────
                        .requestMatchers("/domains/**").authenticated()

                        // ── Account (branding etc.) ───────────────────────────────
                        .requestMatchers("/account/**").authenticated()

                        // ── Dados pessoais (LGPD) ─────────────────────────────────
                        .requestMatchers("/user/**").authenticated()

                        // ── Admin ──────────────────────────────────────────────────
                        .requestMatchers("/admin/**").hasAnyRole("OWNER", "ADMIN")

                        // ── Qualquer outra rota ────────────────────────────────────
                        .anyRequest().authenticated()
                )
                .authenticationProvider(authenticationProvider())
                // ApiKeyAuthFilter antes do JWT — assim X-Api-Key é processado primeiro
                .addFilterBefore(apiKeyAuthFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtAuthFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * Sem entry point próprio, o ExceptionTranslationFilter responde 403 a quem
     * chega sem credencial. Além de errado na semântica HTTP (401 é "não sei quem
     * você é"; 403 é "sei, e você não pode"), isso tinha efeito prático: o
     * interceptor do frontend só derruba a sessão em 401, então um token expirado
     * no meio da navegação deixava o usuário preso — toda chamada falhando, sem
     * ser mandado para o login, até recarregar a página. O que mascarava o
     * problema é /auth/me devolver 401 por conta própria, o que fazia o caminho
     * do boot funcionar e só esse.
     *
     * Quem está autenticado e não tem o papel continua recebendo 403, pelo
     * AccessDeniedHandler padrão.
     */
    @Bean
    public AuthenticationEntryPoint restAuthenticationEntryPoint() {
        return (request, response, ex) -> {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write("{\"error\":\"Autenticação necessária.\"}");
        };
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsServiceImpl);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}