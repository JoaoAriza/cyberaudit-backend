package com.joao.cyberaudit.config;

import com.joao.cyberaudit.security.JwtAuthFilter;
import com.joao.cyberaudit.security.JwtUtil;
import com.joao.cyberaudit.security.UserDetailsServiceImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtUtil               jwtUtil;
    private final UserDetailsServiceImpl userDetailsServiceImpl;

    public SecurityConfig(JwtUtil jwtUtil,
                          UserDetailsServiceImpl userDetailsServiceImpl) {
        this.jwtUtil               = jwtUtil;
        this.userDetailsServiceImpl = userDetailsServiceImpl;
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
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(sm -> sm
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth

                        // ── Públicos sem auth ──────────────────────────────────────
                        .requestMatchers("/auth/**").permitAll()
                        .requestMatchers("/badge/**").permitAll()
                        .requestMatchers("/actuator/health", "/actuator/info").permitAll()

                        // ── Scan passivo e async: público ──────────────────────────
                        .requestMatchers(HttpMethod.GET,  "/scan").permitAll()
                        .requestMatchers(HttpMethod.POST, "/scan/async").permitAll()
                        .requestMatchers(HttpMethod.GET,  "/scan/report").permitAll()
                        .requestMatchers(HttpMethod.GET,  "/scan/debug-headers").permitAll()

                        // ── Scan autenticado ───────────────────────────────────────
                        .requestMatchers(HttpMethod.GET, "/scan/report/pdf").authenticated()
                        .requestMatchers(HttpMethod.GET, "/scan/async/**").authenticated()
                        .requestMatchers("/scan/verify-token", "/scan/verify-check").authenticated()

                        // ── Histórico ──────────────────────────────────────────────
                        .requestMatchers("/history/**").authenticated()

                        // ── Admin ──────────────────────────────────────────────────
                        .requestMatchers("/admin/**").hasAnyRole("OWNER", "ADMIN")

                        // ── Qualquer outra rota ────────────────────────────────────
                        .anyRequest().authenticated()
                )
                .authenticationProvider(authenticationProvider())
                .addFilterBefore(jwtAuthFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsServiceImpl);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}