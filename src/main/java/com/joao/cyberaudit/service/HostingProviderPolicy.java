package com.joao.cyberaudit.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Restrições impostas por quem hospeda a NOSSA instância.
 *
 * O suporte do Render respondeu, por escrito, que não existe pré-aprovação de
 * padrão de tráfego e que o requisito é: o scanner só pode mirar domínios que o
 * usuário possui, e "evitar sondar sistemas do Render ou outros inquilinos".
 *
 * Duas regras distintas saem daí:
 *
 * <ol>
 *   <li><b>Propriedades do próprio provedor</b> ({@code render.com} e
 *       subdomínios): nunca escaneadas, em nenhum modo. Não são alvo de cliente
 *       nenhum — são a infraestrutura de quem nos hospeda.</li>
 *   <li><b>Alvos em infraestrutura compartilhada do provedor</b>
 *       ({@code *.onrender.com}): o resto do scan continua, mas o <b>port scan
 *       não</b>. As portas ali não pertencem ao cliente: são da borda
 *       compartilhada do Render. Sondá-las é literalmente "sondar sistemas do
 *       Render", e o resultado nem seria informação útil sobre o cliente.</li>
 * </ol>
 *
 * Configurável porque a política acompanha o provedor: trocando de host, muda a
 * lista, não o código.
 */
@Service
public class HostingProviderPolicy {

    private final Set<String> neverScan;
    private final Set<String> noPortScan;

    public HostingProviderPolicy(
            @Value("${scan.provider.never-scan-suffixes:render.com}") String neverScanRaw,
            @Value("${scan.provider.no-port-scan-suffixes:onrender.com}") String noPortScanRaw) {
        this.neverScan  = parse(neverScanRaw);
        this.noPortScan = parse(noPortScanRaw);
    }

    /** true se o host é infraestrutura do provedor e não deve ser tocado. */
    public boolean isProviderInfrastructure(String host) {
        return matches(host, neverScan);
    }

    /**
     * true se o host está em infraestrutura compartilhada do provedor, onde as
     * portas abertas são da plataforma e não do cliente.
     */
    public boolean isPortScanForbidden(String host) {
        return matches(host, noPortScan) || matches(host, neverScan);
    }

    private static boolean matches(String host, Set<String> suffixes) {
        if (host == null || host.isBlank() || suffixes.isEmpty()) return false;

        String normalized = host.trim().toLowerCase(Locale.ROOT);
        if (normalized.endsWith(".")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        for (String suffix : suffixes) {
            if (normalized.equals(suffix) || normalized.endsWith("." + suffix)) return true;
        }
        return false;
    }

    private static Set<String> parse(String raw) {
        if (raw == null || raw.isBlank()) return Set.of();
        return Arrays.stream(raw.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(s -> s.toLowerCase(Locale.ROOT))
                .collect(Collectors.toUnmodifiableSet());
    }
}
