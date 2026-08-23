package com.joao.cyberaudit.config;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.xbill.DNS.DohResolver;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.Type;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Resolvedor DNS da aplicação, escolhido por teste no boot.
 *
 * <h2>O problema que isto resolve</h2>
 *
 * O dnsjava consulta por UDP/53 por padrão, e o PaaS bloqueia essa saída. O
 * sintoma é traiçoeiro: {@code Lookup.run()} devolve null em vez de lançar, o
 * scanner conclui "registro ausente" e segue com {@code moduleStatus: OK}. Todo
 * domínio auditado vinha sem SPF, DMARC, DKIM e CAA — google.com incluso.
 *
 * A saída natural seria DNS-over-HTTPS na 443, que é a porta que o resto do
 * scanner já usa. Só que bloquear resolvedores DoH conhecidos também é prática
 * comum de rede: no Render, {@code cloudflare-dns.com} responde "network error"
 * enquanto {@code api.certspotter.com} responde 200 na mesma execução. Ou seja,
 * não é a porta — é o destino.
 *
 * <h2>Por que testar em vez de configurar</h2>
 *
 * Qualquer endpoint fixo é um palpite sobre a rede de quem hospeda, e errar o
 * palpite não dá erro: dá laudo errado. Aqui a aplicação PERGUNTA à própria rede
 * qual caminho funciona, no boot, e registra a resposta no log. Trocar de
 * provedor de hospedagem deixa de exigir investigação.
 *
 * A ordem da lista é a preferência; o sistema (UDP/53) fica por último porque é
 * o que falha nos ambientes que motivaram tudo isto.
 */
@Configuration
public class DnsResolverConfig {

    /** Curto: são sondas de boot, não consultas reais. */
    private static final Duration TIMEOUT_SONDA = Duration.ofSeconds(3);

    /** Nome com registros estáveis e variados, bom para validar um resolvedor. */
    private static final String NOME_SONDA = "cloudflare.com";

    @Value("${dns.resolver:auto}")
    private String modo;

    @Value("${dns.doh-endpoints:https://cloudflare-dns.com/dns-query,https://dns.google/dns-query,https://dns.quad9.net/dns-query}")
    private String endpointsRaw;

    @Value("${dns.timeout-seconds:5}")
    private int timeoutSeconds;

    @PostConstruct
    public void configurar() {
        if ("system".equalsIgnoreCase(modo)) {
            System.out.println("[DnsResolver] modo=system (forçado) — consultas por UDP/53.");
            avisarSeSondaFalhar("system");
            return;
        }

        // O resolvedor do sistema vem primeiro por ser o mais BARATO: um pacote
        // UDP, sem handshake TLS nem requisição HTTP por consulta. O módulo de
        // DNS dispara dezenas de consultas por scan, e o custo por consulta é o
        // que decide se elas cabem no tempo numa instância com CPU limitada.
        // DoH fica como alternativa para rede que bloqueia a 53.
        if (!"doh".equalsIgnoreCase(modo) && sondaFunciona(null)) {
            System.out.println("[DnsResolver] usando o resolvedor do sistema (UDP/53).");
            return;
        }

        List<String> endpoints = Arrays.stream(endpointsRaw.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();

        List<String> recusados = new ArrayList<>();

        for (String endpoint : endpoints) {
            DohResolver resolver = new DohResolver(endpoint);
            resolver.setTimeout(TIMEOUT_SONDA);

            if (sondaFunciona(resolver)) {
                resolver.setTimeout(Duration.ofSeconds(timeoutSeconds));
                Lookup.setDefaultResolver(resolver);
                System.out.println("[DnsResolver] usando DoH em " + endpoint
                        + (recusados.isEmpty() ? "" : " (sem resposta: " + String.join(", ", recusados) + ")"));
                return;
            }
            recusados.add(endpoint);
        }

        System.err.println("[DnsResolver] nem o resolvedor do sistema nem os endpoints DoH ("
                + String.join(", ", recusados) + ") responderam.");
        avisarSeSondaFalhar("system");
    }

    /** Uma consulta real: é a única forma honesta de saber se o caminho existe. */
    private boolean sondaFunciona(Resolver resolver) {
        try {
            Lookup lookup = new Lookup(NOME_SONDA, Type.TXT);
            if (resolver != null) lookup.setResolver(resolver);
            org.xbill.DNS.Record[] registros = lookup.run();
            return registros != null && registros.length > 0;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * O log precisa dizer se DNS funciona AQUI. Sem isso, descobrir que a
     * resolução estava quebrada exigiu escanear o google.com e reparar que ele
     * voltava sem SPF — o tipo de investigação que nenhum operador deveria
     * precisar fazer para saber que o ambiente não coopera.
     */
    private void avisarSeSondaFalhar(String qual) {
        if (sondaFunciona(null)) {
            System.out.println("[DnsResolver] autoteste OK com resolvedor " + qual + ".");
        } else {
            System.err.println("[DnsResolver] AUTOTESTE FALHOU com resolvedor " + qual
                    + ". Os módulos de DNS vão reportar resultado INCONCLUSIVO (não penalizam o score). "
                    + "Libere a saída de rede ou aponte dns.doh-endpoints para um resolvedor alcançável.");
        }
    }
}
