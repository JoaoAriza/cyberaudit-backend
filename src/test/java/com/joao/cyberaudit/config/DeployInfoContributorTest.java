package com.joao.cyberaudit.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.actuate.info.Info;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * O que /actuator/info passa a mostrar sobre o deploy.
 *
 * O env é lido pelo método {@code env}, sobrescrito aqui para simular a Render sem
 * tocar no ambiente real do processo de teste.
 */
class DeployInfoContributorTest {

    /** Contributor com um ambiente fixo, controlado pelo teste. */
    private static DeployInfoContributor comEnv(Map<String, String> env) {
        return new DeployInfoContributor() {
            @Override protected String env(String chave) { return env.get(chave); }
        };
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> deployDe(DeployInfoContributor c) {
        Info.Builder b = new Info.Builder();
        c.contribute(b);
        return (Map<String, Object>) b.build().getDetails().get("deploy");
    }

    @Test
    @DisplayName("na Render, mostra commit encurtado e branch")
    void mostraCommitDaRender() {
        Map<String, Object> deploy = deployDe(comEnv(Map.of(
                "RENDER_GIT_COMMIT", "0123456789abcdef0123456789abcdef01234567",
                "RENDER_GIT_BRANCH", "main")));

        assertEquals("0123456789ab", deploy.get("commit"), "commit deve vir com 12 chars");
        assertEquals("main", deploy.get("branch"));
        assertNotNull(deploy.get("startedAt"));
    }

    @Test
    @DisplayName("sem env (local), não inventa commit — só o horário de subida")
    void semEnvNaoInventaCommit() {
        Map<String, Object> deploy = deployDe(comEnv(new HashMap<>()));

        assertFalse(deploy.containsKey("commit"), "sem variável, não deve haver commit");
        assertFalse(deploy.containsKey("branch"));
        assertNotNull(deploy.get("startedAt"), "startedAt aparece sempre");
    }

    @Test
    @DisplayName("cai no GIT_COMMIT genérico quando não é Render")
    void reservaGenerica() {
        Map<String, Object> deploy = deployDe(comEnv(Map.of("GIT_COMMIT", "abcdef123456")));
        assertEquals("abcdef123456", deploy.get("commit"));
    }

    @Test
    @DisplayName("ignora variável em branco, não a trata como commit")
    void brancoNaoConta() {
        Map<String, Object> deploy = deployDe(comEnv(Map.of(
                "RENDER_GIT_COMMIT", "   ", "GIT_COMMIT", "cafebabe0001")));
        // A da Render está em branco → cai na reserva.
        assertEquals("cafebabe0001", deploy.get("commit"));
        assertTrue(((String) deploy.get("startedAt")).contains("T"), "startedAt é ISO-8601");
    }
}
