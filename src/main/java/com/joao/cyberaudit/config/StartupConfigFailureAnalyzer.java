package com.joao.cyberaudit.config;

import org.springframework.boot.diagnostics.AbstractFailureAnalyzer;
import org.springframework.boot.diagnostics.FailureAnalysis;

import java.util.List;

/**
 * Transforma o erro de configuração no bloco padrão do Spring Boot:
 *
 * <pre>
 *   ***************************
 *   APPLICATION FAILED TO START
 *   ***************************
 *
 *   Description: ...
 *   Action: ...
 * </pre>
 *
 * Esse bloco é impresso no FIM do log e é o único trecho que sobrevive quando
 * alguém copia "as últimas linhas" de um deploy que falhou — que é exatamente
 * o que acontece na prática.
 */
public class StartupConfigFailureAnalyzer
        extends AbstractFailureAnalyzer<InvalidStartupConfigException> {

    @Override
    protected FailureAnalysis analyze(Throwable rootFailure, InvalidStartupConfigException cause) {
        List<String> problems = cause.getProblems();

        StringBuilder description = new StringBuilder(
                problems.size() == 1
                        ? "Há 1 problema na configuração obrigatória:\n\n"
                        : "Há " + problems.size() + " problemas na configuração obrigatória:\n\n");
        for (int i = 0; i < problems.size(); i++) {
            description.append("    ").append(i + 1).append(". ").append(problems.get(i)).append('\n');
        }

        String action = """
                Defina as variáveis de ambiente indicadas acima e faça o redeploy.

                Referência completa: docs/DEPLOY_CHECKLIST.md
                Para gerar segredos:  openssl rand -hex 32""";

        return new FailureAnalysis(description.toString(), action, cause);
    }
}
