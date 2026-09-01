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
    HTTP_FETCH        ("headers",    Fase.PASSIVA),
    RELATED_HOSTS     ("headers",    Fase.PASSIVA),
    ROBOTS            ("recon",      Fase.PASSIVA),
    SECURITY_TXT      ("recon",      Fase.PASSIVA),
    DNS_EMAIL         ("recon",      Fase.PASSIVA),
    HTTP_METHODS      ("http",       Fase.PASSIVA),
    DIRECTORY_LISTING ("dirlist",    Fase.PASSIVA),
    SUBDOMAIN_TAKEOVER("takeover",   Fase.PASSIVA),
    SOURCE_MAPS       ("sourcemap",  Fase.PASSIVA),
    HOST_HEADER       ("hostheader", Fase.PASSIVA),
    API_DOCS          ("apidocs",    Fase.PASSIVA),
    GRAPHQL           ("graphql",    Fase.PASSIVA),
    CERT_TRANSPARENCY ("cert",       Fase.PASSIVA),
    TECH_FINGERPRINT  ("tech",       Fase.PASSIVA),
    CVE               ("cve",        Fase.PASSIVA),

    // ── Ativas ───────────────────────────────────────────────────────────────
    CORS              ("active",     Fase.ATIVA),
    SENSITIVE_FILES   ("active",     Fase.ATIVA),
    WAF               ("active",     Fase.ATIVA),
    PORT_SCAN         ("active",     Fase.ATIVA),
    REFLECTED_XSS     ("active",     Fase.ATIVA),
    DB_ERROR          ("active",     Fase.ATIVA),
    OPEN_REDIRECT     ("redirect",   Fase.ATIVA),
    CRLF              ("crlf",       Fase.ATIVA),
    PATH_TRAVERSAL    ("traversal",  Fase.ATIVA),
    SSRF              ("ssrf",       Fase.ATIVA);

    /**
     * Em que fase do scan a verificação roda.
     *
     * A distinção já existia como comentário separando os dois blocos deste enum, e
     * como o parâmetro {@code active} lá no orquestrador. Virou dado porque o feed
     * de progresso precisa dela em dois momentos: para não listar as ativas num scan
     * passivo (elas nunca vão rodar, e uma linha eternamente pendente parece travada)
     * e para agrupar o que aparece na tela.
     */
    public enum Fase { PASSIVA, ATIVA }

    private final String moduloUi;
    private final Fase   fase;

    ScanCheck(String moduloUi, Fase fase) {
        this.moduloUi = moduloUi;
        this.fase     = fase;
    }

    /** Id do módulo na barra lateral do Frontend. */
    public String moduloUi() {
        return moduloUi;
    }

    public Fase fase() {
        return fase;
    }

    /** Só roda quando o scan é ativo — envia requisição com payload ao alvo. */
    public boolean ativa() {
        return fase == Fase.ATIVA;
    }
}
