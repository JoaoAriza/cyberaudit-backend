package com.joao.cyberaudit;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

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

        SpringApplication.run(CyberauditApplication.class, args);
    }
}