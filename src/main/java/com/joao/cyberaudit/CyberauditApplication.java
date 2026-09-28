package com.joao.cyberaudit;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

import java.security.Security;
import java.util.TimeZone;

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

        pinTimeZone();
        pinDnsCache();

        SpringApplication.run(CyberauditApplication.class, args);
    }

    /**
     * Fixa o TTL do cache de DNS da JVM.
     *
     * Não é mais a defesa contra DNS rebinding — isso agora é responsabilidade do
     * {@code SsrfPinningResolverProvider} (JEP 418), que fixa o endereço exato
     * validado pelo {@code SsrfGuard} para qualquer resolução seguinte do mesmo
     * host, sem depender de cache. Este TTL fica só por higiene de performance:
     * com TTL 0 (padrão quando não há SecurityManager) cada uma das dezenas de
     * requisições que um scan faz ao mesmo domínio dispararia uma consulta DNS nova.
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

    /**
     * Fixa o fuso da JVM em UTC.
     *
     * Todo LocalDateTime.now() da aplicação — auditoria, agendamento, validade de
     * token, histórico — passa a significar a mesma coisa na máquina do dev
     * (UTC-3) e no contêiner do Render (UTC). Sem isso o mesmo código grava horas
     * de fusos diferentes na MESMA coluna, e a linha não guarda nada que permita
     * saber depois qual é qual.
     *
     * Também é o que sustenta o "Z" que o TimeConfig carimba na saída da API:
     * carimbar UTC em hora que não é UTC seria pior do que não carimbar.
     *
     * Precisa rodar antes do Spring subir — pool de conexões, agendador e Jackson
     * leem TimeZone.getDefault() na inicialização.
     */
    private static void pinTimeZone() {
        TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
    }
}
