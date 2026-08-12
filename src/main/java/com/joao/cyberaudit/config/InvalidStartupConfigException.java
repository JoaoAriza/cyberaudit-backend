package com.joao.cyberaudit.config;

import java.util.List;

/**
 * Configuração obrigatória ausente ou inválida, detectada antes de o contexto subir.
 *
 * Existe como tipo próprio para que o {@link StartupConfigFailureAnalyzer} possa
 * transformá-la no bloco "APPLICATION FAILED TO START" que o Spring imprime no
 * FIM do log — que é onde as pessoas efetivamente olham quando um deploy falha.
 * Jogar a mensagem em System.err no meio do boot não resolve: ela fica soterrada.
 */
public class InvalidStartupConfigException extends RuntimeException {

    private final List<String> problems;

    public InvalidStartupConfigException(List<String> problems) {
        super("Configuração inválida: " + String.join(" | ", problems));
        this.problems = List.copyOf(problems);
    }

    public List<String> getProblems() {
        return problems;
    }
}
