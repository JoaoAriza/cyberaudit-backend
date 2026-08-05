package com.joao.cyberaudit.config;

import org.springframework.context.annotation.Configuration;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Headers de segurança de TODA resposta da API.
 *
 * Esta é uma API REST: não serve HTML e não usa cookies de sessão. A CSP aqui
 * não protege uma página — protege o caso em que uma resposta é aberta direto no
 * navegador (relatório, badge SVG, mensagem de erro), impedindo que ela execute
 * script ou seja embutida em um frame de terceiro. A CSP do SPA é separada e vive
 * no frontend.
 */
@Configuration
public class SecurityHeadersConfig implements Filter {

    /**
     * `frame-ancestors` não herda de `default-src` e é ignorado em `<meta>` — só
     * funciona como header, que é o que fazemos aqui. `base-uri`/`form-action`/
     * `object-src` fecham vetores que `default-src` também não cobre sozinho.
     */
    private static final String CSP = String.join("; ",
            "default-src 'none'",
            "frame-ancestors 'none'",
            "base-uri 'none'",
            "form-action 'none'",
            "object-src 'none'",
            "script-src 'none'",
            "style-src 'unsafe-inline'",   // badge SVG usa atributos de estilo
            "img-src 'self' data:",
            "sandbox");

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletResponse httpResponse = (HttpServletResponse) response;

        httpResponse.setHeader("X-Content-Type-Options", "nosniff");
        httpResponse.setHeader("X-Frame-Options", "DENY");
        httpResponse.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
        httpResponse.setHeader("Content-Security-Policy", CSP);

        // Não vazar a URL da API (que carrega host/params de scan) para terceiros.
        httpResponse.setHeader("Referrer-Policy", "no-referrer");

        // API nenhuma precisa de câmera, microfone, geolocalização ou pagamento.
        httpResponse.setHeader("Permissions-Policy",
                "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
                        + "magnetometer=(), microphone=(), payment=(), usb=()");

        // Respostas de API não podem ficar em cache compartilhado: muitas carregam
        // dados da conta (histórico, assinatura, chaves) e o gating por plano faz a
        // MESMA URL devolver conteúdo diferente por usuário. O badge é a exceção —
        // é público, imutável por 5 min e define o próprio Cache-Control.
        if (!isPublicCacheable(request)) {
            httpResponse.setHeader("Cache-Control", "no-store");
        }

        chain.doFilter(request, response);
    }

    private boolean isPublicCacheable(ServletRequest request) {
        if (!(request instanceof jakarta.servlet.http.HttpServletRequest http)) return false;
        String path = http.getRequestURI();
        return path != null && path.startsWith("/badge/");
    }
}
