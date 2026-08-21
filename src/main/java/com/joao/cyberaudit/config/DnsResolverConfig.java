package com.joao.cyberaudit.config;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.xbill.DNS.DohResolver;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Type;

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
        autoTeste();
    }

    /**
     * Uma consulta conhecida no boot, para o log dizer se DNS funciona AQUI.
     *
     * Sem isto, descobrir que a resolução estava quebrada exigiu escanear o
     * google.com e reparar que ele vinha sem SPF. O ambiente é que decide se a
     * saída de rede existe, então o ambiente é que precisa responder — no boot,
     * em uma linha, antes de qualquer cliente receber um laudo errado.
     */
    private void autoTeste() {
        try {
            Lookup lookup = new Lookup("cloudflare.com", Type.TXT);
            org.xbill.DNS.Record[] registros = lookup.run();

            if (registros != null && registros.length > 0) {
                System.out.println("[DnsResolver] autoteste OK — "
                        + registros.length + " registro(s) para cloudflare.com.");
            } else {
                System.err.println("[DnsResolver] AUTOTESTE FALHOU (" + lookup.getErrorString()
                        + "). Os módulos de DNS vão reportar resultado inconclusivo. "
                        + "Verifique a saída de rede ou troque dns.doh-endpoint.");
            }
        } catch (Exception e) {
            System.err.println("[DnsResolver] AUTOTESTE FALHOU: " + e.getMessage());
        }
    }
}
