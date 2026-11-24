package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.CookieFinding;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

@Service
public class CookieSecurityService {

    /** Como o {@code sameSite} do {@link CookieFinding} registra "sem SameSite válido". */
    public static final String SAMESITE_AUSENTE = "MISSING";

    // Códigos de CookieFinding.problems. São as chaves do texto no catálogo (evidence.*).
    public static final String SEM_SECURE                 = "COOKIE_SEM_SECURE";
    public static final String SEM_HTTPONLY               = "COOKIE_SEM_HTTPONLY";
    public static final String SEM_SAMESITE               = "COOKIE_SEM_SAMESITE";
    public static final String SAMESITE_NONE_SEM_SECURE   = "COOKIE_SAMESITE_NONE_SEM_SECURE";

    /** Todo cookie do Hotjar começa assim. */
    private static final String PREFIXO_HOTJAR = "_hj";

    private final MessageCatalog catalog;

    public CookieSecurityService(MessageCatalog catalog) {
        this.catalog = catalog;
    }

    public List<CookieFinding> analyze(List<String> rawSetCookies) {
        List<CookieFinding> findings = new ArrayList<>();
        if (rawSetCookies == null || rawSetCookies.isEmpty()) return findings;

        for (String raw : rawSetCookies) {
            CookieFinding f = evaluate(raw);
            if (f != null) findings.add(f);
        }
        return findings;
    }

    /** O que o cookie é decide o que falta nele importar. */
    enum Tipo {
        /** Identifica a sessão/autenticação: roubá-lo é entrar como o usuário. */
        SESSAO,
        /** Token anti-CSRF: feito para o JavaScript ler (double-submit) — HttpOnly quebraria. */
        CSRF,
        /** Preferência, consentimento, analytics: vazar não dá acesso a nada. */
        OUTRO
    }

    /**
     * Severidade por tipo (BUG-12). Só cookie de sessão custa ponto: o que falta
     * nele é o caminho para sequestrar a conta. Nos outros o problema continua
     * listado no card, como LOW — informação, sem desconto.
     */
    private CookieFinding evaluate(String raw) {
        if (raw == null || raw.isBlank()) return null;

        // RFC 6265 §5.2: o primeiro pedaço é nome=valor, o resto são atributos. O
        // atributo é o NOME antes do "=", sem caixa e sem espaço. Lia por substring
        // do header inteiro: "secure" no nome ou no valor do cookie virava a flag.
        String[] parts = raw.split(";");
        String nameVal = parts[0].trim();
        String name    = nameVal.contains("=") ? nameVal.split("=", 2)[0].trim() : nameVal;

        boolean httpOnly = false;
        boolean secure   = false;
        String  sameSite = SAMESITE_AUSENTE;
        for (int i = 1; i < parts.length; i++) {
            String av    = parts[i].trim();
            int    igual = av.indexOf('=');
            String attr  = (igual < 0 ? av : av.substring(0, igual)).trim().toLowerCase(Locale.ROOT);
            String valor = igual < 0 ? "" : av.substring(igual + 1).trim();
            switch (attr) {
                case "secure"   -> secure = true;
                case "httponly" -> httpOnly = true;
                // Repetido, vale o último — como no navegador.
                case "samesite" -> sameSite = sameSite(valor);
                default         -> { }
            }
        }

        Tipo tipo     = tipo(name);
        boolean sessao = tipo == Tipo.SESSAO;

        // O veredito do card. Cada problema entra duas vezes: o código, em `problems`,
        // e o texto do catálogo, em `issues` (o que a tela e o laudo mostram). Quem
        // precisa saber o que está errado lê o código (BUG-13).
        List<String> codigos = new ArrayList<>();
        String risk = "LOW";

        if (!secure) {
            codigos.add(SEM_SECURE);
            risk = escalate(risk, sessao ? "HIGH" : "LOW");
        }
        // Token CSRF é feito para o JavaScript ler (double-submit): HttpOnly quebraria.
        if (!httpOnly && tipo != Tipo.CSRF) {
            codigos.add(SEM_HTTPONLY);
            risk = escalate(risk, sessao ? "HIGH" : "LOW");
        }
        if (SAMESITE_AUSENTE.equals(sameSite)) {
            codigos.add(SEM_SAMESITE);
            risk = escalate(risk, sessao ? "MEDIUM" : "LOW");
        } else if ("None".equals(sameSite) && !secure) {
            codigos.add(SAMESITE_NONE_SEM_SECURE);
            risk = escalate(risk, sessao ? "HIGH" : "LOW");
        }

        if (codigos.isEmpty()) return null;

        List<String> textos = new ArrayList<>();
        for (String codigo : codigos) textos.add(catalog.evidence(codigo));
        return new CookieFinding(name, httpOnly, secure, sameSite, risk,
                String.join("; ", textos), List.copyOf(codigos));
    }

    /**
     * Valor fora de Strict/Lax/None faz o navegador ignorar o atributo
     * (RFC 6265bis §5.6.7) — é como não ter SameSite. Antes saía "UNKNOWN" e não
     * contava como problema.
     */
    private static String sameSite(String valor) {
        return switch (valor.toLowerCase(Locale.ROOT)) {
            case "strict" -> "Strict";
            case "lax"    -> "Lax";
            case "none"   -> "None";
            default       -> SAMESITE_AUSENTE;
        };
    }

    /**
     * A regra única de "que cookie é este". O card (risco e nota) e o painel "O que
     * está em jogo" ({@link ImpactLabelService}) leem daqui. O painel tinha lista
     * própria e as duas divergiam (BUG-21).
     */
    static Tipo tipo(String name) {
        if (name == null) return Tipo.OUTRO;
        String l = name.toLowerCase(Locale.ROOT);
        // CSRF antes de sessão: XSRF-TOKEN e csrftoken contêm "token" e caíam como
        // sessão — o XSRF-TOKEN do Laravel perdia 10 pontos por não ter HttpOnly.
        if (l.contains("csrf") || l.contains("xsrf")) return Tipo.CSRF;
        // Hotjar (_hjSession_1873402, _hjSessionUser_..., _hjIncludedInSessionSample_...):
        // analytics gravado pelo JavaScript da página, que nunca terá HttpOnly e não
        // abre conta nenhuma. O "session" do nome é a visita, não o login (BUG-21).
        if (l.startsWith(PREFIXO_HOTJAR)) return Tipo.OUTRO;
        return isSessionCookie(l) ? Tipo.SESSAO : Tipo.OUTRO;
    }

    private static boolean isSessionCookie(String l) {
        return l.contains("session") || l.contains("token") || l.contains("auth")
                || l.contains("jwt") || l.contains("login") || l.contains("sess")
                || l.equals("phpsessid") || l.equals("jsessionid")
                || l.equals("asp.net_sessionid")
                // connect.sid (Express) e afins. "sid" solto ou como sufixo — no meio
                // da palavra ("inside_banner") não é sessão.
                || l.equals("sid") || l.endsWith(".sid") || l.endsWith("_sid") || l.endsWith("-sid");
    }

    private String escalate(String current, String candidate) {
        return rankOf(candidate) > rankOf(current) ? candidate : current;
    }

    private int rankOf(String risk) {
        return switch (risk) { case "HIGH" -> 3; case "MEDIUM" -> 2; default -> 1; };
    }
}