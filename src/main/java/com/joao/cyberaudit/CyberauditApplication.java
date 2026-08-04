package com.joao.cyberaudit;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

import java.security.Security;

@SpringBootApplication
@EnableAsync
@EnableScheduling
public class CyberauditApplication {
    public static void main(String[] args) {
        // Libera o header "Host" (restrito por padrão no HttpClient do JDK) para o probe
        // de Host Header Injection. Deve ser definido antes de qualquer HttpClient ser
        // criado (a propriedade é lida uma única vez na init) e respeita valor pré-existente.
        String restricted = System.getProperty("jdk.httpclient.allowRestrictedHeaders");
        if (restricted == null || restricted.isBlank()) {
            System.setProperty("jdk.httpclient.allowRestrictedHeaders", "host");
        } else if (!restricted.toLowerCase().contains("host")) {
            System.setProperty("jdk.httpclient.allowRestrictedHeaders", restricted + ",host");
        }

        pinDnsCache();

        SpringApplication.run(CyberauditApplication.class, args);
    }

    /**
     * Fixa o TTL do cache de DNS da JVM para reduzir a janela de DNS rebinding.
     *
     * O SsrfGuard resolve o host para validar e o HttpClient resolve de novo para
     * conectar. Com TTL 0 (padrão quando não há SecurityManager) um alvo hostil pode
     * responder um IP público na primeira resolução e 169.254.169.254 na segunda.
     * Com TTL positivo as duas resoluções vêm da mesma entrada de cache.
     *
     * Precisa rodar antes do primeiro InetAddress.getByName do processo — a política
     * é lida uma única vez na inicialização de InetAddressCachePolicy.
     */
    private static void pinDnsCache() {
        setIfAbsent("networkaddress.cache.ttl",
                System.getenv().getOrDefault("DNS_CACHE_TTL_SECONDS", "30"));
        setIfAbsent("networkaddress.cache.negative.ttl", "5");
    }

    private static void setIfAbsent(String property, String value) {
        String current = Security.getProperty(property);
        if (current == null || current.isBlank() || "0".equals(current.trim())
                || "-1".equals(current.trim())) {
            Security.setProperty(property, value);
        }
    }
}