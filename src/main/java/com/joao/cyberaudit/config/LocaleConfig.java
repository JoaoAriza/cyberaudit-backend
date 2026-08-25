package com.joao.cyberaudit.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.i18n.AcceptHeaderLocaleResolver;

import java.util.List;
import java.util.Locale;

/**
 * Idioma da resposta.
 *
 * Duas fontes, nesta ordem:
 *
 *  1. {@code ?lang=} — escolha explícita do usuário na interface. Precede o
 *     cabeçalho porque quem troca o idioma na tela está justamente dizendo que
 *     não quer o do navegador.
 *  2. {@code Accept-Language} — o padrão do navegador.
 *
 * Idioma não suportado cai no português, e não no locale do SERVIDOR: a lista de
 * suportados fecha isso aqui, e {@code spring.messages.fallback-to-system-locale=false}
 * fecha do lado do catálogo. Sem os dois, o resultado mudaria conforme a máquina
 * onde a aplicação roda.
 *
 * Idioma novo entra na lista abaixo mais o arquivo {@code messages_<idioma>.properties} —
 * nada além disso.
 */
@Configuration
public class LocaleConfig {

    public static final Locale PADRAO = Locale.forLanguageTag("pt-BR");

    /** Ordem é preferência quando o Accept-Language traz vários com o mesmo peso. */
    public static final List<Locale> SUPORTADOS = List.of(PADRAO, Locale.ENGLISH);

    @Bean
    public LocaleResolver localeResolver() {
        AcceptHeaderLocaleResolver resolver = new AcceptHeaderLocaleResolver() {
            @Override
            public Locale resolveLocale(HttpServletRequest request) {
                Locale explicito = doParametro(request.getParameter("lang"));
                return explicito != null ? explicito : super.resolveLocale(request);
            }
        };
        resolver.setDefaultLocale(PADRAO);
        resolver.setSupportedLocales(SUPORTADOS);
        return resolver;
    }

    /**
     * Casa por IDIOMA, não por locale completo: quem pede {@code en-GB} recebe o
     * catálogo em inglês em vez de cair no português por causa da região.
     *
     * @return null quando o parâmetro está ausente ou pede idioma que não temos —
     *         nesse caso a decisão volta para o Accept-Language.
     */
    public static Locale doParametro(String bruto) {
        if (bruto == null || bruto.isBlank()) return null;
        Locale pedido = Locale.forLanguageTag(bruto.trim());
        for (Locale suportado : SUPORTADOS) {
            if (suportado.getLanguage().equals(pedido.getLanguage())) return suportado;
        }
        return null;
    }
}
