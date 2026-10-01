package com.joao.cyberaudit.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Libera hostnames específicos (os serviços do docker-compose de teste do
 * `cyberaudit-qa`) da checagem de IP interno/privado do {@link SsrfGuard}.
 *
 * Existe SÓ sob o profile {@code qa-docker} — fora dele o Spring nem instancia
 * esta classe, então {@link SsrfGuard#setTestAllowlist} nunca é chamado e a
 * allowlist fica sempre vazia. Não é um `if` de profile escrito à mão: é o
 * `@Profile` do Spring decidindo se o bean chega a existir.
 */
@Component
@Profile("qa-docker")
public class SsrfTestAllowlistConfig {

    public SsrfTestAllowlistConfig(@Value("${ssrf.test-allowlist:}") String raw) {
        Set<String> hosts = (raw == null || raw.isBlank())
                ? Set.of()
                : Arrays.stream(raw.split(","))
                        .map(String::trim)
                        .filter(s -> !s.isEmpty())
                        .map(s -> s.toLowerCase(Locale.ROOT))
                        .collect(Collectors.toUnmodifiableSet());
        SsrfGuard.setTestAllowlist(hosts);
        System.out.println("[SsrfGuard] profile qa-docker ativo — allowlist de teste: " + hosts);
    }
}
