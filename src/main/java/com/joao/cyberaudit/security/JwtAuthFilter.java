package com.joao.cyberaudit.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class JwtAuthFilter extends OncePerRequestFilter {

    /**
     * Únicas rotas alcançáveis com token pre-auth (senha OK, 2FA pendente).
     *
     * Era `/auth/2fa/**`, o que incluía os endpoints de SETUP — entre eles
     * `DELETE /auth/2fa/totp` e `DELETE /auth/2fa/email`. Quem tivesse só a senha
     * desativava o próprio 2FA da vítima e entrava sem segundo fator. O allowlist
     * agora é exato e cobre apenas o que o login precisa.
     */
    private static final Set<String> PRE_AUTH_ALLOWED_PATHS = Set.of(
            "/auth/2fa/verify",
            "/auth/2fa/send-email-otp");

    private final JwtUtil jwtUtil;
    private final UserDetailsServiceImpl userDetailsService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public JwtAuthFilter(JwtUtil jwtUtil, UserDetailsServiceImpl userDetailsService) {
        this.jwtUtil           = jwtUtil;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain)
            throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            chain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(7);

        if (!jwtUtil.isValid(token)) {
            chain.doFilter(request, response);
            return;
        }

        boolean twoFactorPending = jwtUtil.isTwoFactorPending(token);

        if (twoFactorPending && !PRE_AUTH_ALLOWED_PATHS.contains(normalizedPath(request))) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            objectMapper.writeValue(response.getWriter(),
                    Map.of("error", "2FA_PENDING",
                           "message", "Complete a verificação 2FA antes de continuar."));
            return;
        }

        String email = jwtUtil.extractEmail(token);
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(email);
            // Token pre-auth nunca carrega as authorities reais do usuário: mesmo que
            // uma rota escape do allowlist acima, ele não satisfaz nenhuma checagem
            // de role (/admin/**, ações OWNER-only).
            var authorities = twoFactorPending
                    ? List.<GrantedAuthority>of(new SimpleGrantedAuthority("ROLE_PRE_AUTH"))
                    : userDetails.getAuthorities();
            UsernamePasswordAuthenticationToken auth =
                    new UsernamePasswordAuthenticationToken(userDetails, null, authorities);
            auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(auth);
        }

        chain.doFilter(request, response);
    }

    /**
     * Caminho normalizado (decodificado, sem `..`, sem barra final) para comparar
     * com o allowlist.
     *
     * {@code getRequestURI()} devolve o caminho CRU: o Tomcat normaliza antes de
     * rotear, mas o filtro veria o valor original. Com um `startsWith`, uma URI como
     * `/auth/2fa/../../admin/users` passava no filtro e era roteada para /admin.
     * Aqui o allowlist é por igualdade exata, então qualquer forma inesperada
     * simplesmente não casa e cai no 403.
     */
    private String normalizedPath(HttpServletRequest request) {
        String uri = request.getRequestURI();
        if (uri == null) return "";

        String context = request.getContextPath();
        if (context != null && !context.isEmpty() && uri.startsWith(context)) {
            uri = uri.substring(context.length());
        }

        try {
            uri = URLDecoder.decode(uri, StandardCharsets.UTF_8);
            String normalized = URI.create(uri).normalize().getPath();
            if (normalized != null) uri = normalized;
        } catch (Exception ignored) {
            // Caminho malformado: segue com o valor cru — não casa com o allowlist.
        }

        while (uri.length() > 1 && uri.endsWith("/")) {
            uri = uri.substring(0, uri.length() - 1);
        }
        return uri;
    }
}