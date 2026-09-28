package com.joao.cyberaudit.service;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.net.spi.InetAddressResolver;
import java.net.spi.InetAddressResolverProvider;
import java.util.List;
import java.util.stream.Stream;

/**
 * Resolvedor DNS da JVM (JEP 418, Java 18+) que fecha o TOCTOU descrito no
 * Javadoc de {@link SsrfGuard}: fixa, para hosts já validados, os mesmos
 * endereços que o {@link SsrfGuard} resolveu — em vez de deixar o
 * {@code HttpClient} consultar o DNS de novo por conta própria ao conectar.
 *
 * Registrado via {@code META-INF/services/java.net.spi.InetAddressResolverProvider}
 * (SPI padrão do {@code java.net.InetAddress}). Ativo para TODA resolução de
 * hostname do processo, mas só intercepta hosts com pin vivo em
 * {@link ScanDnsPinRegistry} — qualquer outro host (banco, SMTP, APIs
 * externas) cai direto no resolvedor padrão da JVM, sem overhead nem mudança
 * de comportamento.
 */
public final class SsrfPinningResolverProvider extends InetAddressResolverProvider {

    @Override
    public InetAddressResolver get(Configuration configuration) {
        InetAddressResolver builtin = configuration.builtinResolver();

        return new InetAddressResolver() {
            @Override
            public Stream<InetAddress> lookupByName(String host, LookupPolicy lookupPolicy)
                    throws UnknownHostException {
                List<InetAddress> pinned = ScanDnsPinRegistry.get(host);
                if (pinned != null) return pinned.stream();
                return builtin.lookupByName(host, lookupPolicy);
            }

            @Override
            public String lookupByAddress(byte[] addr) throws UnknownHostException {
                return builtin.lookupByAddress(addr);
            }
        };
    }

    @Override
    public String name() {
        return "cyberaudit-ssrf-pinning";
    }
}
