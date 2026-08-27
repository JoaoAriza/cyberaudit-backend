package com.joao.cyberaudit.model;

/**
 * Uma verificação do scan, com o módulo da interface que ela alimenta.
 *
 * Existe por dois motivos, os dois nascidos do mesmo defeito: o resultado dizia
 * "1 verificação não concluída" sem dizer QUAL, e a barra lateral marcava o módulo
 * com ✓ verde mesmo quando a verificação dele não tinha rodado — um "seguro" que o
 * scan nunca chegou a apurar.
 *
 * <ul>
 *   <li>{@code name()} é a chave estável no {@code ScanResult.moduleStatus}. Era
 *       prosa em inglês ("HTTP fetch / headers"), que não dá para traduzir nem para
 *       casar com nada;</li>
 *   <li>{@link #moduloUi()} é o id do módulo na barra lateral, e é o que permite o
 *       aviso aparecer no lugar certo. Várias verificações caem no mesmo módulo —
 *       WAF, CORS e port scan são todas "active";</li>
 *   <li>o nome de exibição vem do catálogo em {@code check.<NOME>}, como todo texto
 *       que chega ao cliente.</li>
 * </ul>
 *
 * Verificação nova entra aqui e no catálogo. Sem entrada no enum ela não tem como
 * ser reportada — que é melhor do que aparecer sem nome.
 */
public enum ScanCheck {

    // ── Passivas ─────────────────────────────────────────────────────────────
    HTTP_FETCH        ("headers"),
    RELATED_HOSTS     ("headers"),
    ROBOTS            ("recon"),
    SECURITY_TXT      ("recon"),
    DNS_EMAIL         ("recon"),
    HTTP_METHODS      ("http"),
    DIRECTORY_LISTING ("dirlist"),
    SUBDOMAIN_TAKEOVER("takeover"),
    SOURCE_MAPS       ("sourcemap"),
    HOST_HEADER       ("hostheader"),
    API_DOCS          ("apidocs"),
    GRAPHQL           ("graphql"),
    CERT_TRANSPARENCY ("cert"),
    TECH_FINGERPRINT  ("tech"),
    CVE               ("cve"),

    // ── Ativas ───────────────────────────────────────────────────────────────
    CORS              ("active"),
    SENSITIVE_FILES   ("active"),
    WAF               ("active"),
    PORT_SCAN         ("active"),
    REFLECTED_XSS     ("active"),
    DB_ERROR          ("active"),
    OPEN_REDIRECT     ("redirect"),
    CRLF              ("crlf"),
    PATH_TRAVERSAL    ("traversal"),
    SSRF              ("ssrf");

    private final String moduloUi;

    ScanCheck(String moduloUi) {
        this.moduloUi = moduloUi;
    }

    /** Id do módulo na barra lateral do Frontend. */
    public String moduloUi() {
        return moduloUi;
    }
}
