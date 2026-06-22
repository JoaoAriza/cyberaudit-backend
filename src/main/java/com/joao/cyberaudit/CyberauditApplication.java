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
        // Permite que o HostHeaderService injete o header "Host" (restrito por padrão
        // no HttpClient do JDK). Sem isso, o probe de Host Header Injection lança
        // IllegalArgumentException silenciosamente e o vetor mais importante (Host)
        // nunca é testado de fato.
        //
        // O JDK lê esta propriedade UMA ÚNICA VEZ na inicialização da classe interna
        // de rede, então ela precisa ser definida ANTES de qualquer HttpClient ser
        // criado — i.e., antes do SpringApplication.run() instanciar os beans.
        // Respeita valor pré-existente (ex: -D no deploy), apenas garante "host" na lista.
        String restricted = System.getProperty("jdk.httpclient.allowRestrictedHeaders");
        if (restricted == null || restricted.isBlank()) {
            System.setProperty("jdk.httpclient.allowRestrictedHeaders", "host");
        } else if (!restricted.toLowerCase().contains("host")) {
            System.setProperty("jdk.httpclient.allowRestrictedHeaders", restricted + ",host");
        }

        SpringApplication.run(CyberauditApplication.class, args);
    }
}