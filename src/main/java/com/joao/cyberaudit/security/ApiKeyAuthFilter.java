package com.joao.cyberaudit.security;

import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.service.ApiKeyService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

/**
 * Autentica requests que carregam o header X-Api-Key.
 * Deve ser inserido ANTES do JwtAuthFilter na chain.
 *
 * Se já houver autenticação no contexto (ex: JWT processado primeiro), não faz nada.
 */
public class ApiKeyAuthFilter extends OncePerRequestFilter {

    public static final String HEADER = "X-Api-Key";

    private final ApiKeyService apiKeyService;

    public ApiKeyAuthFilter(ApiKeyService apiKeyService) {
        this.apiKeyService = apiKeyService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain)
            throws ServletException, IOException {

        String rawKey = request.getHeader(HEADER);
        if (rawKey == null || rawKey.isBlank()) {
            chain.doFilter(request, response);
            return;
        }

        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            chain.doFilter(request, response);
            return;
        }

        Optional<AppUser> userOpt = apiKeyService.validate(rawKey);
        if (userOpt.isPresent()) {
            AppUser user = userOpt.get();
            UsernamePasswordAuthenticationToken auth =
                    new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
            auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(auth);
        }
        // Se inválida, não autentica — o request continua como anônimo
        // (o endpoint decidirá se exige autenticação)

        chain.doFilter(request, response);
    }
}
