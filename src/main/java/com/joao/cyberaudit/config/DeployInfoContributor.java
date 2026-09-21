package com.joao.cyberaudit.config;

import org.springframework.boot.actuate.info.Info;
import org.springframework.boot.actuate.info.InfoContributor;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Diz QUAL versão está no ar — sem depender do {@code .git}.
 *
 * O problema recorrente: {@code /actuator/info} vinha vazio, então "será que o
 * deploy subiu?" não tinha resposta de fora, e toda dúvida virava adivinhação. Um
 * plugin git-commit-id não resolve aqui: o {@code Dockerfile} copia só
 * {@code pom.xml} e {@code src} (e o {@code .dockerignore} exclui {@code .git}),
 * então no build da imagem não há repositório para ler.
 *
 * A saída em duas pontas:
 *   - {@code build.*} (versão + data do build) vem do goal build-info do
 *     spring-boot-maven-plugin — sempre presente, diz QUANDO o jar foi montado.
 *   - o COMMIT vem daqui, da variável que a plataforma injeta em runtime. Na
 *     Render é {@code RENDER_GIT_COMMIT} / {@code RENDER_GIT_BRANCH}; deixo um
 *     {@code GIT_COMMIT} / {@code GIT_BRANCH} genérico como reserva para outro
 *     provedor. Fora deles (local), o commit simplesmente não aparece — e o
 *     {@code build.time} já basta para saber se o build local é o atual.
 *
 * Só expõe commit, branch e horário de subida. Nada de varrer o ambiente inteiro
 * — por isso {@code management.info.env.enabled=false} continua valendo.
 */
@Component
public class DeployInfoContributor implements InfoContributor {

    /** Quando ESTE processo subiu — proxy de "há quanto tempo este deploy está no ar". */
    private final Instant startedAt = Instant.now();

    @Override
    public void contribute(Info.Builder builder) {
        Map<String, Object> deploy = new LinkedHashMap<>();

        String commit = firstNonBlank(env("RENDER_GIT_COMMIT"), env("GIT_COMMIT"));
        String branch = firstNonBlank(env("RENDER_GIT_BRANCH"), env("GIT_BRANCH"));

        // Commit encurtado: 12 chars bastam para identificar e não poluem o JSON.
        if (commit != null) deploy.put("commit", commit.length() > 12 ? commit.substring(0, 12) : commit);
        if (branch != null) deploy.put("branch", branch);
        deploy.put("startedAt", startedAt.toString());

        builder.withDetail("deploy", deploy);
    }

    /** Isolado e sobrescrevível para o teste exercitar sem mexer no ambiente real. */
    protected String env(String chave) {
        return System.getenv(chave);
    }

    private static String firstNonBlank(String... valores) {
        for (String v : valores) if (v != null && !v.isBlank()) return v;
        return null;
    }
}
