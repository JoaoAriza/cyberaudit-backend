package com.joao.cyberaudit.config;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.xbill.DNS.DohResolver;
import org.xbill.DNS.Lookup;

import java.time.Duration;

/**
 * Resolvedor DNS da aplicação.
 *
 * <h2>Por que DNS-over-HTTPS e não o resolvedor do sistema</h2>
 *
 * O dnsjava consulta por UDP/53 por padrão. Em PaaS essa saída costuma ser
 * bloqueada, e o sintoma é traiçoeiro: {@code Lookup.run()} devolve null em vez
 * de lançar erro, então o scanner conclui "registro ausente" e segue com
 * {@code moduleStatus: OK}. Nada aparece no log.
 *
 * O efeito em produção era o pior possível para um produto de auditoria: TODO
 * domínio escaneado voltava sem SPF, sem DMARC, sem DKIM e sem CAA, com risco de
 * spoofing CRITICAL. Verificado escaneando google.com — que tem os quatro — e
 * recebendo o mesmo veredito. O cliente lê um laudo errado e vai "corrigir" algo
 * que já está certo.
 *
 * Saindo pela 443, a consulta usa o mesmo caminho que todo o resto do scanner já
 * usa com sucesso (HTTP, crt.sh, robots.txt). Se essa porta fechasse, nenhum
 * módulo funcionaria — ou seja, não introduz um novo ponto de falha silenciosa.
 *
 * {@code DNS_RESOLVER=system} volta ao comportamento antigo, para quem roda em
 * infraestrutura própria onde a 53 está liberada e o resolvedor local é mais
 * rápido.
 */
@Configuration
public class DnsResolverConfig {

    @Value("${dns.resolver:doh}")
    private String modo;

    @Value("${dns.doh-endpoint:https://cloudflare-dns.com/dns-query}")
    private String dohEndpoint;

    @Value("${dns.timeout-seconds:5}")
    private int timeoutSeconds;

    @PostConstruct
    public void configurar() {
        if ("system".equalsIgnoreCase(modo)) {
            System.out.println("[DnsResolver] modo=system — consultas por UDP/53.");
            return;
        }

        DohResolver resolver = new DohResolver(dohEndpoint);
        resolver.setTimeout(Duration.ofSeconds(timeoutSeconds));

        // Lookup.setDefaultResolver afeta todo uso de Lookup na JVM, que é
        // justamente o alcance desejado: DnsSecurityService e
        // SubdomainTakeoverService passam a resolver pelo mesmo caminho.
        Lookup.setDefaultResolver(resolver);

        System.out.println("[DnsResolver] modo=doh — consultas via " + dohEndpoint);
    }
}
