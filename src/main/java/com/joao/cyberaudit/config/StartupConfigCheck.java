package com.joao.cyberaudit.config;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;

import java.util.ArrayList;
import java.util.List;

/**
 * Confere a configuração obrigatória ANTES de o Spring criar qualquer bean, e
 * reporta TODOS os problemas de uma vez.
 *
 * Sem isto, cada erro de configuração aparece como um stack trace de
 * BeanCreationException com a causa real enterrada no fim da cadeia de
 * "Caused by" — e, pior, um por vez: corrige o JWT, redeploya, descobre o
 * banco, redeploya, descobre o CORS. Em PaaS, onde cada ciclo leva minutos e
 * não dá para depurar em arquivo, isso custa caro.
 *
 * Roda como EnvironmentPostProcessor (registrado em META-INF/spring.factories)
 * porque é o único ponto que já enxerga TODAS as fontes de propriedade — env
 * vars da plataforma e o .env local — e ainda assim acontece antes da criação
 * dos beans.
 */
public class StartupConfigCheck implements EnvironmentPostProcessor {

    private static final int MIN_SECRET_LENGTH = 32;

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment env, SpringApplication application) {
        List<String> errors   = new ArrayList<>();
        List<String> warnings = new ArrayList<>();

        // ── Impedem a aplicação de funcionar ─────────────────────────────────
        String jwtSecret = env.getProperty("jwt.secret");
        if (isBlank(jwtSecret)) {
            errors.add("JWT_SECRET não está definido (ou está vazio).");
        } else if (jwtSecret.length() < MIN_SECRET_LENGTH) {
            errors.add("JWT_SECRET tem " + jwtSecret.length() + " caracteres; o mínimo é "
                    + MIN_SECRET_LENGTH + " (HMAC-SHA256 exige 256 bits).");
        }

        if (isBlank(env.getProperty("spring.datasource.password"))) {
            errors.add("DB_PASSWORD não está definido.");
        }

        String dbUrl = env.getProperty("spring.datasource.url");
        if (isBlank(dbUrl)) {
            errors.add("DB_URL não está definido.");
        } else if (!dbUrl.startsWith("jdbc:")) {
            // Erro clássico em PaaS: colar a connection string do painel direto.
            errors.add("DB_URL precisa estar no formato JDBC e começar com 'jdbc:postgresql://'. "
                    + "Painéis costumam mostrar 'postgresql://usuario:senha@host/banco' — converta "
                    + "para 'jdbc:postgresql://host:5432/banco' e ponha usuário e senha em "
                    + "DB_USERNAME e DB_PASSWORD.");
        }

        String origins = env.getProperty("cors.allowed-origins");
        if (isBlank(origins)) {
            errors.add("ALLOWED_ORIGINS não está definido.");
        } else if (origins.contains("*")) {
            errors.add("ALLOWED_ORIGINS contém '*'. Use as origens reais do frontend.");
        }

        // ── Sobem, mas com um controle desligado ─────────────────────────────
        if (isBlank(env.getProperty("platform.staff-emails"))) {
            warnings.add("PLATFORM_STAFF_EMAILS vazio: NINGUÉM poderá dispensar a prova de "
                    + "posse de domínio em scan ativo, nem você.");
        }

        boolean mpAtivo = !isBlank(env.getProperty("mp.access-token"));
        if (mpAtivo && isBlank(env.getProperty("mp.webhook-secret"))) {
            warnings.add("MP_ACCESS_TOKEN definido mas MP_WEBHOOK_SECRET vazio: o webhook vai "
                    + "recusar TODAS as notificações (401) e nenhum pagamento confirmado subirá "
                    + "de plano.");
        }

        if ("0".equals(env.getProperty("app.trusted-proxy-count", "0"))
                && !isBlank(env.getProperty("PORT"))) {
            // PORT definido = quase certamente atrás do proxy de uma plataforma.
            warnings.add("TRUSTED_PROXY_COUNT=0 num ambiente que injeta PORT: se houver proxy na "
                    + "frente, todos os visitantes serão contados como um só IP e os limites de "
                    + "guest, login e rate-limit não vão distinguir ninguém.");
        }

        if (!warnings.isEmpty()) {
            System.err.println(banner("⚠  AVISOS DE CONFIGURAÇÃO", warnings,
                    "A aplicação vai subir, mas os pontos acima merecem atenção."));
        }

        if (!errors.isEmpty()) {
            System.err.println(banner("✖  CONFIGURAÇÃO INVÁLIDA — a aplicação não vai subir", errors,
                    "Corrija as variáveis acima no painel do provedor e faça o redeploy."));
            throw new IllegalStateException(
                    "Configuração inválida: " + String.join(" | ", errors));
        }
    }

    private static String banner(String title, List<String> lines, String footer) {
        StringBuilder sb = new StringBuilder("\n");
        String rule = "═".repeat(78);
        sb.append(rule).append('\n').append(title).append('\n').append(rule).append('\n');
        for (int i = 0; i < lines.size(); i++) {
            sb.append("  ").append(i + 1).append(". ").append(lines.get(i)).append('\n');
        }
        sb.append(rule).append('\n').append(footer).append('\n').append(rule).append('\n');
        return sb.toString();
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
