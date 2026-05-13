package com.joao.cyberaudit.config;

import com.joao.cyberaudit.security.JwtAuthFilter;
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
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtAuthFilter    jwtAuthFilter;
    private final UserDetailsService userDetailsService;

    public SecurityConfig(JwtAuthFilter jwtAuthFilter, UserDetailsService userDetailsService) {
        this.jwtAuthFilter    = jwtAuthFilter;
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth

                        // ── Públicos sem auth ──────────────────────────────────
                        .requestMatchers("/auth/login", "/auth/setup").permitAll()
                        .requestMatchers("/auth/accept-invite/**").permitAll()
                        .requestMatchers("/badge/**").permitAll()
                        .requestMatchers("/actuator/health", "/actuator/info").permitAll()

                        // ── Scan passivo: público (limite por IP no service)
                        // Scan ativo: checado dentro do ScanController
                        .requestMatchers(HttpMethod.GET, "/scan").permitAll()
                        .requestMatchers(HttpMethod.POST, "/scan/async").permitAll()
                        .requestMatchers(HttpMethod.GET, "/scan/async/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/scan/report").permitAll()

                        // ── Verify token/check: requer autenticação
                        .requestMatchers("/scan/verify-token", "/scan/verify-check").authenticated()

                        // ── Histórico: apenas autenticados
                        .requestMatchers("/history/**").authenticated()

                        // ── Admin: apenas OWNER (configurado na Fase C)
                        .requestMatchers("/admin/**").hasRole("OWNER")

                        // ── Qualquer outra rota: autenticado
                        .anyRequest().authenticated()
                )
                .authenticationProvider(authenticationProvider())
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}