package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.DnsSecurityResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.MXRecord;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Service
public class DnsSecurityService {

    /**
     * Seletores DKIM conhecidos por provider, consultados em paralelo. Seletores
     * baseados em data (ex: Google "20161025") não são adivinháveis; se nenhum for
     * encontrado o resultado é NOT_DETECTED (inconclusivo), não MISSING.
     */
    private static final List<String> DKIM_SELECTORS = List.of(
            // Genéricos
            "default", "dkim", "dkim1", "dkim2", "mail", "email", "key1", "key2",
            // Google Workspace
            "google",
            // Microsoft 365
            "selector1", "selector2",
            // SendGrid
            "s1", "s2", "em", "smtpapi",
            // Mailchimp / Mandrill
            "k1", "k2", "k3", "mandrill",
            // Amazon SES
            "amazonses",
            // Mailgun
            "mx1", "mx2", "pic", "krs",
            // Postmark
            "pm",
            // FastMail
            "fm1", "fm2", "fm3",
            // Proton Mail
            "protonmail", "protonmail2", "protonmail3",
            // Zoho Mail
            "zoho",
            // HubSpot
            "hubspot1", "hubspot2",
            // Mailjet
            "mailjet",
            // SparkPost
            "scph",
            // Resend — publica em `resend._domainkey`. Sem este seletor o scanner
            // reportava DKIM ausente em domínios que o têm corretamente
            // configurado, e ainda inflava o risco de spoofing por tabela.
            "resend",
            // Brevo (Sendinblue)
            "brevo",
            // ConvertKit
            "ck1",
            // Campaign Monitor
            "cm",
            // ActiveCampaign
            "ac",
            // OVH
            "ovhex"
    );

    /**
     * Provedor de e-mail reconhecível pelo SPF ou pelo MX, e os seletores que ele
     * publica.
     *
     * @param marcadores trechos que aparecem num `include:` do SPF ou no destino de
     *                   um MX. Casam por substring em minúsculas.
     */
    record ProvedorDeEmail(String nome, List<String> marcadores, List<String> seletores) {}

    /**
     * De onde sai o palpite dirigido de DKIM.
     *
     * O SPF e o MX já dizem QUEM entrega o e-mail do domínio — `include:_spf.google.com`
     * e `aspmx.l.google.com` são a mesma informação escrita de dois jeitos. Como as duas
     * consultas já foram feitas na fase 1, o provedor sai de graça, e com ele os únicos
     * seletores que têm chance real de existir.
     *
     * Um domínio pode casar com MAIS DE UM provedor, e isso é o caso comum, não a
     * exceção: recebe no Google e envia pelo SendGrid. Por isso o casamento devolve
     * lista, não o primeiro que bater.
     */
    private static final List<ProvedorDeEmail> PROVEDORES = List.of(
            new ProvedorDeEmail("Google Workspace",
                    List.of("_spf.google.com", "aspmx.l.google.com", "googlemail.com"),
                    List.of("google")),
            new ProvedorDeEmail("Microsoft 365",
                    List.of("spf.protection.outlook.com", "mail.protection.outlook.com"),
                    List.of("selector1", "selector2")),
            new ProvedorDeEmail("SendGrid",
                    List.of("sendgrid.net"),
                    List.of("s1", "s2", "em", "smtpapi")),
            new ProvedorDeEmail("Mailchimp / Mandrill",
                    List.of("spf.mandrillapp.com", "servers.mcsv.net", "mailchimp.com"),
                    List.of("k1", "k2", "k3", "mandrill")),
            // `amazonses.com` é marcador do Resend TAMBÉM, e não por precaução: o Resend
            // entrega pela infra da AWS e é isso — só isso — que o SPF dele publica.
            // Conferido no cyberauditapp.com, cujo SPF é `v=spf1 include:amazonses.com -all`
            // e cujo DKIM está em `resend._domainkey`. Sem este marcador a rodada dirigida
            // tentaria só `amazonses`, não acharia, e o domínio cairia na força bruta —
            // exatamente o que esta etapa existe para evitar. Como o casamento devolve
            // lista, os dois provedores entram e são 2 seletores em vez de 40.
            new ProvedorDeEmail("Resend",
                    List.of("resend.com", "_spf.resend.com", "amazonses.com"),
                    List.of("resend")),
            new ProvedorDeEmail("Amazon SES",
                    List.of("amazonses.com"),
                    List.of("amazonses")),
            new ProvedorDeEmail("Mailgun",
                    List.of("mailgun.org", "mailgun.net"),
                    List.of("mx1", "mx2", "pic", "krs")),
            new ProvedorDeEmail("Postmark",
                    List.of("spf.mtasv.net", "mtasv.net"),
                    List.of("pm")),
            new ProvedorDeEmail("FastMail",
                    List.of("messagingengine.com"),
                    List.of("fm1", "fm2", "fm3")),
            new ProvedorDeEmail("Proton Mail",
                    List.of("protonmail.ch", "protonmail.com", "proton.me"),
                    List.of("protonmail", "protonmail2", "protonmail3")),
            new ProvedorDeEmail("Zoho Mail",
                    List.of("zoho.com", "zoho.eu", "zohomail"),
                    List.of("zoho")),
            new ProvedorDeEmail("HubSpot",
                    List.of("hubspotemail.net", "hubspot.com"),
                    List.of("hubspot1", "hubspot2")),
            new ProvedorDeEmail("Mailjet",
                    List.of("mailjet.com"),
                    List.of("mailjet")),
            new ProvedorDeEmail("SparkPost",
                    List.of("sparkpostmail.com"),
                    List.of("scph")),
            new ProvedorDeEmail("Brevo (Sendinblue)",
                    List.of("brevo.com", "sendinblue.com"),
                    List.of("brevo")),
            new ProvedorDeEmail("ConvertKit",
                    List.of("convertkit.com"),
                    List.of("ck1")),
            new ProvedorDeEmail("Campaign Monitor",
                    List.of("cmail1.com", "createsend.com"),
                    List.of("cm")),
            new ProvedorDeEmail("ActiveCampaign",
                    List.of("activecampaign.com"),
                    List.of("ac")),
            new ProvedorDeEmail("OVH",
                    List.of("mx.ovh.com", "ovh.net"),
                    List.of("ovhex"))
    );

    /**
     * O que a fase 1 descobre e a fase 2 aproveita.
     *
     * Escrito pelas análises de SPF e MX, lido pela sonda de DKIM. É um holder à parte
     * e não o próprio builder porque o builder do Lombok não tem como ser LIDO — e a
     * evidência precisa atravessar as duas fases. As referências são atômicas porque
     * SPF e MX rodam em threads diferentes.
     */
    /** Teto de tempo das DUAS rodadas de DKIM somadas — o mesmo que a sonda antiga tinha. */
    private static final long DKIM_ORCAMENTO_MS = 8_000;

    private static final class PistasDeProvedor {
        private final AtomicReference<String>       spf = new AtomicReference<>("");
        private final AtomicReference<List<String>> mx  = new AtomicReference<>(List.of());

        void spf(String registro)          { if (registro != null)   spf.set(registro); }
        void mx(List<String> registros)    { if (registros != null && !registros.isEmpty()) mx.set(registros); }

        /** SPF e MX num texto só, minúsculo — é contra ele que os marcadores casam. */
        String evidencia() {
            return (spf.get() + " " + String.join(" ", mx.get())).toLowerCase(Locale.ROOT);
        }
    }

    private static final Pattern DMARC_P = Pattern.compile(
            "(?:^|;)\\s*p=([^;\\s]+)", Pattern.CASE_INSENSITIVE
    );

    /** Política dos SUBDOMÍNIOS. Precede `p=` quando o registro é herdado. */
    private static final Pattern DMARC_SP = Pattern.compile(
            "(?:^|;)\\s*sp=([^;\\s]+)", Pattern.CASE_INSENSITIVE
    );

    private static final Logger log = LoggerFactory.getLogger(DnsSecurityService.class);

    private final PublicSuffixService publicSuffixService;

    public DnsSecurityService(PublicSuffixService publicSuffixService) {
        this.publicSuffixService = publicSuffixService;
    }

    /**
     * Executa a consulta e diferencia ausência de indisponibilidade.
     *
     * O dnsjava devolve {@code null} de {@code run()} nos dois casos. O código de
     * {@link Lookup#getResult()} é o que separa:
     * {@code TYPE_NOT_FOUND}/{@code HOST_NOT_FOUND} significam que perguntamos e
     * o registro não existe; {@code TRY_AGAIN}/{@code UNRECOVERABLE} significam
     * que a pergunta não chegou — e aí afirmar "ausente" é inventar resultado.
     *
     * @param falhou marcado quando a causa foi de rede
     * @return registros encontrados, ou null se não existem / não deu para saber
     */
    /** Ponto final = nome absoluto, imune à search list de quem hospeda. */
    String nomeAbsoluto(String nome) {
        if (nome == null || nome.isBlank()) return nome;
        String limpo = nome.trim();
        return limpo.endsWith(".") ? limpo : limpo + ".";
    }

    private org.xbill.DNS.Record[] consultar(String nome, int tipo, AtomicBoolean falhou) {
        try {
            // Nome ABSOLUTO (com ponto final). Sem o ponto, o dnsjava trata como
            // relativo e aplica a search list do /etc/resolv.conf — em container,
            // isso vira consulta a "<alvo>.<search-do-cluster>", que volta
            // NXDOMAIN. O scanner então concluía "sem SPF" para domínios que têm.
            //
            // Auditar domínio é sempre pergunta absoluta: a search list da máquina
            // onde a aplicação roda não tem nada a ver com o alvo. É também o que
            // explica funcionar na estação de trabalho e falhar no deploy.
            Lookup lookup = new Lookup(nomeAbsoluto(nome), tipo);
            org.xbill.DNS.Record[] registros = lookup.run();

            if (registros == null
                    && (lookup.getResult() == Lookup.TRY_AGAIN
                     || lookup.getResult() == Lookup.UNRECOVERABLE)) {
                falhou.set(true);
                log.warn("Consulta DNS falhou para {} tipo {}: {} — o resultado NÃO significa "
                        + "registro ausente. Verifique dns.resolver/saída de rede.",
                        nome, tipo, lookup.getErrorString());
            }
            return registros;
        } catch (Exception e) {
            falhou.set(true);
            log.warn("Consulta DNS lançou para {} tipo {}: {}", nome, tipo, e.getMessage());
            return null;
        }
    }

    /**
     * As análises rodam em DUAS FASES, e a ordem é o ponto principal deste método.
     *
     * SPF, DMARC, CAA e MX somam ~8 consultas e são as que decidem o veredito. A
     * sondagem de DKIM são ~84 consultas especulativas contra nomes que, na
     * esmagadora maioria, não existem — ela só tenta adivinhar o seletor.
     *
     * Rodando tudo junto, as 8 essenciais disputavam conexão com as 84
     * descartáveis. Em instância com CPU limitada elas perdiam a disputa e
     * voltavam com timeout, e o scanner concluía "sem SPF, sem DMARC" para
     * domínios que têm ambos. O sintoma era intermitente e variava por domínio —
     * assinatura de contenção de recurso, não de rede bloqueada.
     *
     * Separando as fases, o que importa consulta com banda livre. O DKIM continua
     * sendo feito, depois e com concorrência baixa: se não couber no tempo, o
     * resultado honesto dele já é NOT_DETECTED.
     */
    public DnsSecurityResult scan(String host) {
        DnsSecurityResult.DnsSecurityResultBuilder b = DnsSecurityResult.builder();
        AtomicBoolean falhou = new AtomicBoolean(false);
        PistasDeProvedor pistas = new PistasDeProvedor();

        // ── Fase 1: o que decide o risco ──────────────────────────────────
        ExecutorService pool = Executors.newFixedThreadPool(4);
        try {
            var spfFuture   = CompletableFuture.runAsync(() -> analyzeSpf(host, falhou, b, pistas), pool);
            var dmarcFuture = CompletableFuture.runAsync(() -> analyzeDmarc(host, falhou, b), pool);
            var caaFuture   = CompletableFuture.runAsync(() -> analyzeCaa(host, falhou, b),   pool);
            var mxFuture    = CompletableFuture.runAsync(() -> analyzeMx(host, falhou, b, pistas), pool);

            CompletableFuture.allOf(spfFuture, dmarcFuture, caaFuture, mxFuture)
                    .get(10, TimeUnit.SECONDS);

        } catch (Exception e) {
            falhou.set(true);
            b.summary("Erro ao consultar DNS: " + e.getMessage());
        } finally {
            pool.shutdownNow();
        }

        // ── Fase 2: DKIM, melhor-esforço ──────────────────────────────────
        // Fora do try acima de propósito: falha aqui não é falha do módulo.
        // Recebe as pistas da fase 1: o provedor revelado pelo SPF e pelo MX é o que
        // transforma a adivinhação de seletor num palpite dirigido.
        analyzeDkim(host, b, pistas);

        b.lookupFailed(falhou.get());
        DnsSecurityResult result = b.build();
        result.setEmailSpoofingRisk(calculateRisk(result));
        result.setSummary(buildSummary(result));
        return result;
    }

    // ── SPF ───────────────────────────────────────────────────────────────────

    private void analyzeSpf(String host, AtomicBoolean falhou,
                            DnsSecurityResult.DnsSecurityResultBuilder b,
                            PistasDeProvedor pistas) {
        // SPF normalmente fica no apex. Tenta o host, depois o domínio registrável (apex).
        if (querySpf(host, falhou, b, pistas)) return;

        String parent = publicSuffixService.registrableDomain(host);
        if (parent != null && !parent.equals(host)) {
            querySpf(parent, falhou, b, pistas);
        }
        // querySpf marca MISSING se nada for encontrado
    }

    /**
     * Consulta SPF no domínio dado e popula o builder.
     * @return true se um registro v=spf1 válido foi encontrado
     */
    private boolean querySpf(String domain, AtomicBoolean falhou,
                             DnsSecurityResult.DnsSecurityResultBuilder b,
                             PistasDeProvedor pistas) {
        try {
            List<String> spfs = textosQueComecamCom(
                    consultar(domain, Type.TXT, falhou), "v=spf1");

            if (spfs.isEmpty()) { b.spfPresent(false).spfPolicy("MISSING"); return false; }

            // Vale como pista mesmo quando o registro é inválido: SPF duplicado não
            // protege ninguém, mas ainda diz quem entrega o e-mail do domínio.
            pistas.spf(String.join(" ", spfs));

            if (spfs.size() > 1) {
                // RFC 7208 §4.5: mais de um registro v=spf1 é PERMERROR — o
                // receptor descarta TODOS. Na prática o domínio está sem SPF.
                // Reportar o primeiro como válido esconderia uma configuração
                // quebrada justamente de quem contratou a auditoria para achá-la.
                b.spfPresent(true)
                 .spfRecord(spfs.size() + " registros SPF (inválido): " + String.join(" | ", spfs))
                 .spfPolicy("INVALID");
                return true;
            }

            String content = spfs.get(0);
            b.spfPresent(true).spfRecord(content);

            String lower = content.toLowerCase(Locale.ROOT);
            if      (lower.contains("-all")) b.spfPolicy("STRONG");
            else if (lower.contains("~all")) b.spfPolicy("MEDIUM");
            else if (lower.contains("+all") || lower.contains("?all")) b.spfPolicy("WEAK");
            else                             b.spfPolicy("MEDIUM");
            return true;

        } catch (Exception e) {
            b.spfPresent(false).spfPolicy("MISSING");
            return false;
        }
    }

    /**
     * Extrai os TXT que começam com o prefixo, já concatenando os pedaços.
     *
     * TXT acima de 255 bytes é publicado em várias strings e precisa ser
     * remontado — chave DKIM e SPF longo caem nesse caso. Retornar a LISTA (e não
     * o primeiro) é o que permite detectar duplicidade, que é erro de config.
     */
    private List<String> textosQueComecamCom(org.xbill.DNS.Record[] records, String prefixo) {
        List<String> saida = new ArrayList<>();
        if (records == null) return saida;

        for (org.xbill.DNS.Record r : records) {
            if (!(r instanceof TXTRecord txt)) continue;
            StringBuilder sb = new StringBuilder();
            for (Object parte : txt.getStrings()) sb.append(parte);
            String conteudo = sb.toString().trim();
            if (conteudo.toLowerCase(Locale.ROOT).startsWith(prefixo.toLowerCase(Locale.ROOT))) {
                saida.add(conteudo);
            }
        }
        return saida;
    }

    // ── DMARC ─────────────────────────────────────────────────────────────────

    private void analyzeDmarc(String host, AtomicBoolean falhou,
                              DnsSecurityResult.DnsSecurityResultBuilder b) {
        // RFC 7489 §6.6.3: receivers fall back to org domain if subdomain has no record.
        // We mirror this: try the host first, then the parent domain.
        if (queryDmarc(host, falhou, b, false)) return;

        String parent = publicSuffixService.registrableDomain(host);
        if (parent != null && !parent.equals(host)) {
            // Herdando do domínio organizacional, quem vale para o subdomínio é
            // `sp=` quando existe — ver RFC 7489 §6.3. Ler sempre `p=` reportava
            // "fraco" para domínios que publicam p=none; sp=reject, que é uma
            // configuração deliberada e forte para os subdomínios.
            queryDmarc(parent, falhou, b, true);
        }
        // queryDmarc sets MISSING if nothing was found
    }

    /**
     * Queries _dmarc.<domain> and populates the builder.
     * @return true if a valid DMARC record was found and parsed
     */
    private boolean queryDmarc(String domain, AtomicBoolean falhou,
                               DnsSecurityResult.DnsSecurityResultBuilder b,
                               boolean herdadoDoOrganizacional) {
        try {
            List<String> dmarcs = textosQueComecamCom(
                    consultar("_dmarc." + domain, Type.TXT, falhou), "v=DMARC1");

            if (dmarcs.isEmpty()) { b.dmarcPresent(false).dmarcPolicy("MISSING"); return false; }

            if (dmarcs.size() > 1) {
                // RFC 7489 §6.6.3: com mais de um registro, o receptor age como
                // se não houvesse nenhum. Mesma lógica do SPF duplicado.
                b.dmarcPresent(true)
                 .dmarcRecord(dmarcs.size() + " registros DMARC (inválido): " + String.join(" | ", dmarcs))
                 .dmarcPolicy("INVALID");
                return true;
            }

            String content = dmarcs.get(0);
            b.dmarcPresent(true).dmarcRecord(content);

            // Para subdomínio herdando do organizacional, `sp=` tem precedência.
            String politica = null;
            if (herdadoDoOrganizacional) politica = extrair(DMARC_SP, content);
            if (politica == null)        politica = extrair(DMARC_P,  content);

            if (politica == null) {
                // `p=` é obrigatório: sem ele o registro não é acionável.
                b.dmarcPolicy("WEAK");
            } else {
                switch (politica.toLowerCase(Locale.ROOT).trim()) {
                    case "reject"     -> b.dmarcPolicy("STRONG");
                    case "quarantine" -> b.dmarcPolicy("MEDIUM");
                    default           -> b.dmarcPolicy("WEAK");
                }
            }
            return true;

        } catch (Exception ignored) {}
        b.dmarcPresent(false).dmarcPolicy("MISSING");
        return false;
    }

    private String extrair(Pattern p, String texto) {
        Matcher m = p.matcher(texto);
        return m.find() ? m.group(1) : null;
    }

    // ── DKIM — seletores testados em paralelo ─────────────────────────────────

    /**
     * O DKIM não tem como ser descoberto: o seletor é um nome arbitrário escolhido por
     * quem configurou. A única saída é adivinhar — e a diferença está em adivinhar às
     * cegas ou com evidência.
     *
     * <h2>Duas rodadas</h2>
     *
     * <b>Dirigida.</b> O SPF e o MX, já consultados na fase 1, dizem quem entrega o
     * e-mail do domínio. Reconhecido o provedor, só os seletores DELE têm chance real:
     * são 2 a 12 consultas em vez de ~84. É o caso comum — a esmagadora maioria dos
     * domínios usa um punhado de provedores conhecidos.
     *
     * <b>Reserva.</b> Se nenhum provedor foi reconhecido, ou se o reconhecido não
     * respondeu, cai na lista inteira. Desistir depois da rodada dirigida perderia
     * DKIM que a força bruta achava: quem RECEBE por um provedor pode ENVIAR por outro,
     * e nem toda infra aparece no SPF.
     *
     * <h2>Por que o DKIM não alimenta o sinal de falha global</h2>
     *
     * São consultas especulativas contra nomes que na maioria não existem. Se algumas
     * estouram o tempo — esperado num lote grande, ainda mais em instância com CPU
     * limitada —, isso não diz nada sobre a saúde do DNS: o SPF e o DMARC podem ter
     * resolvido perfeitamente em uma consulta cada.
     *
     * Deixar o lote de DKIM marcar falha global fazia o resultado inteiro virar UNKNOWN
     * por causa da parte mais especulativa da análise. O DKIM já tem seu próprio estado
     * honesto para isso: NOT_DETECTED — que significa inconclusivo, não ausente. Seletor
     * customizado ou baseado em data (ex: Google "20230601") não é adivinhável, e nunca
     * será, com tabela nenhuma.
     */
    private void analyzeDkim(String host,
                             DnsSecurityResult.DnsSecurityResultBuilder b,
                             PistasDeProvedor pistas) {
        // Isolado do sinal global: ver javadoc acima.
        AtomicBoolean falhou = new AtomicBoolean(false);

        // Sonda no host e no apex: DKIM costuma estar em selector._domainkey.<apex>.
        List<String> domains = new ArrayList<>();
        domains.add(host);
        String parent = publicSuffixService.registrableDomain(host);
        if (parent != null && !parent.equals(host)) domains.add(parent);

        List<ProvedorDeEmail> provedores = provedoresParaEvidencia(pistas.evidencia());
        List<String> dirigidos = provedores.stream()
                .flatMap(p -> p.seletores().stream())
                .distinct()
                .toList();

        // Orçamento ÚNICO para as duas rodadas. Sem ele, um domínio cujo provedor é
        // reconhecido mas não responde pagaria os 4s da dirigida MAIS os 8s da reserva
        // — a etapa que existe para economizar consulta acabaria custando tempo.
        long limite = System.currentTimeMillis() + DKIM_ORCAMENTO_MS;

        if (!dirigidos.isEmpty()) {
            String seletor = sondarSeletores(domains, dirigidos, falhou, segundosRestantes(limite, 4));
            if (seletor != null) {
                log.debug("DKIM de {} resolvido no seletor {} — provedor revelado por SPF/MX: {}",
                        host, seletor,
                        provedores.stream().map(ProvedorDeEmail::nome).collect(Collectors.joining(", ")));
                b.dkimHintFound(true).dkimSelector(seletor);
                return;
            }
        }

        // O que a rodada dirigida já testou sai da reserva — repetir consulta que
        // acabou de falhar não muda a resposta e só gasta o orçamento de tempo.
        List<String> resto = DKIM_SELECTORS.stream()
                .filter(s -> !dirigidos.contains(s))
                .toList();

        String seletor = sondarSeletores(domains, resto, falhou, segundosRestantes(limite, 8));
        if (seletor != null) b.dkimHintFound(true).dkimSelector(seletor);
        else                 b.dkimHintFound(false).dkimSelector("NOT_DETECTED");
    }

    /** Segundos que ainda cabem no orçamento, limitados a {@code teto} e nunca zero. */
    private static int segundosRestantes(long limiteMs, int teto) {
        long restam = (limiteMs - System.currentTimeMillis() + 999) / 1000;
        return (int) Math.max(1, Math.min(teto, restam));
    }

    /**
     * Provedores de e-mail que o SPF e o MX do domínio revelam.
     *
     * Devolve LISTA porque casar com mais de um é o caso comum, não a exceção: recebe
     * no Google e envia pelo SendGrid, com os dois no mesmo SPF. Ficar no primeiro que
     * bate perderia metade dos seletores certos.
     *
     * Estático e visível ao pacote para o teste poder exercitar a tabela sem rede —
     * é a parte da etapa que tem regra de negócio; o resto é consulta DNS.
     *
     * @param evidencia SPF e MX concatenados, como {@code PistasDeProvedor.evidencia()} monta
     */
    static List<ProvedorDeEmail> provedoresParaEvidencia(String evidencia) {
        if (evidencia == null || evidencia.isBlank()) return List.of();

        String texto = evidencia.toLowerCase(Locale.ROOT);
        return PROVEDORES.stream()
                .filter(p -> p.marcadores().stream().anyMatch(texto::contains))
                .toList();
    }

    /**
     * Dispara um lote de sondas e devolve o primeiro seletor que existir, ou null.
     *
     * Concorrência baixa de propósito: 20 threads disparando 84 consultas de uma vez
     * saturavam o cliente HTTP (no modo DoH, cada consulta é uma requisição) e
     * derrubavam por timeout até o SPF e o DMARC. Adivinhar seletor não justifica
     * atrapalhar o que decide o veredito.
     */
    private String sondarSeletores(List<String> domains, List<String> seletores,
                                   AtomicBoolean falhou, int timeoutSegundos) {
        if (seletores.isEmpty()) return null;

        List<String[]> probes = new ArrayList<>();   // {selector, domain}
        for (String domain : domains)
            for (String selector : seletores)
                probes.add(new String[]{ selector, domain });

        int poolSize = Math.min(Math.max(probes.size(), 1), 4);
        ExecutorService pool = Executors.newFixedThreadPool(poolSize);
        List<CompletableFuture<String>> futures = probes.stream()
                .map(p -> CompletableFuture.supplyAsync(() -> {
                    try {
                        org.xbill.DNS.Record[] records =
                                consultar(p[0] + "._domainkey." + p[1], Type.TXT, falhou);
                        return (records != null && records.length > 0) ? p[0] : null;
                    } catch (Exception e) { return null; }
                }, pool))
                .toList();
        try {
            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                    .get(timeoutSegundos, TimeUnit.SECONDS);
        } catch (Exception e) {
            // Estouro de tempo no lote não descarta o que já voltou: a colheita abaixo
            // roda de qualquer jeito. Um seletor confirmado é um seletor confirmado,
            // mesmo que as sondas vizinhas não tenham cabido no tempo.
            log.debug("Lote de DKIM não concluiu em {}s — colhendo o que respondeu", timeoutSegundos);
        } finally {
            pool.shutdownNow();
        }

        return futures.stream()
                .map(f -> f.getNow(null))
                .filter(Objects::nonNull)
                .findFirst()
                .orElse(null);
    }

    // ── CAA ───────────────────────────────────────────────────────────────────

    /**
     * CAA também precisa cair para o apex, como SPF e DMARC.
     *
     * Consultando só o host, um alvo `www.exemplo.com` nunca encontrava o CAA —
     * que é publicado em `exemplo.com`. Todo domínio escaneado pelo www aparecia
     * sem CAA, mesmo tendo. (A herança de CAA para subdomínios é resolvida pela
     * CA na emissão; para efeito de auditoria, o que vale é existir no apex.)
     */
    private void analyzeCaa(String host, AtomicBoolean falhou,
                            DnsSecurityResult.DnsSecurityResultBuilder b) {
        // RFC 8659 §3: a busca sobe LABEL A LABEL até o apex, e para no primeiro
        // nível que tiver CAA. Pular direto para o domínio registrável ignorava
        // níveis intermediários — num alvo `www.loja.exemplo.com`, um CAA em
        // `loja.exemplo.com` passava despercebido.
        String apex  = publicSuffixService.registrableDomain(host);
        String atual = host;

        while (atual != null && !atual.isEmpty()) {
            if (queryCaa(atual, falhou, b)) return;

            // Não sobe além do domínio registrável: acima dele é sufixo público
            // (`com.br`, `com`), que não pertence a quem está sendo auditado.
            if (atual.equals(apex)) break;

            int ponto = atual.indexOf('.');
            if (ponto < 0) break;
            atual = atual.substring(ponto + 1);
        }
        b.caaPresent(false);
    }

    private boolean queryCaa(String domain, AtomicBoolean falhou,
                             DnsSecurityResult.DnsSecurityResultBuilder b) {
        try {
            org.xbill.DNS.Record[] records = consultar(domain, Type.CAA, falhou);
            if (records == null || records.length == 0) { b.caaPresent(false); return false; }

            // caaRecord (singular) é o que a UI mostra; caaRecords carrega a lista
            // inteira, que é o que a checagem de emissor no CT precisa ver.
            List<String> todos = Arrays.stream(records)
                    .map(org.xbill.DNS.Record::toString)
                    .collect(Collectors.toList());

            b.caaPresent(true).caaRecord(records[0].toString()).caaRecords(todos);
            return true;
        } catch (Exception e) {
            b.caaPresent(false);
            return false;
        }
    }

    // ── MX ────────────────────────────────────────────────────────────────────

    private void analyzeMx(String host, AtomicBoolean falhou,
                           DnsSecurityResult.DnsSecurityResultBuilder b,
                           PistasDeProvedor pistas) {
        // MX normalmente fica no apex. Tenta o host, depois o domínio registrável (apex).
        if (queryMx(host, falhou, b, pistas)) return;

        String parent = publicSuffixService.registrableDomain(host);
        if (parent != null && !parent.equals(host)) {
            queryMx(parent, falhou, b, pistas);
        }
    }

    /**
     * Consulta MX no domínio dado e popula o builder.
     * @return true se ao menos um registro MX foi encontrado
     */
    private boolean queryMx(String domain, AtomicBoolean falhou,
                            DnsSecurityResult.DnsSecurityResultBuilder b,
                            PistasDeProvedor pistas) {
        try {
            org.xbill.DNS.Record[] records = consultar(domain, Type.MX, falhou);
            if (records == null || records.length == 0) {
                b.mxPresent(false).mxRecords(List.of());
                return false;
            }
            List<String> mx = new ArrayList<>();
            for (org.xbill.DNS.Record r : records) {
                if (r instanceof MXRecord mxr)
                    mx.add(mxr.getPriority() + " " + mxr.getTarget());
            }
            b.mxPresent(true).mxRecords(mx);
            pistas.mx(mx);
            return true;
        } catch (Exception e) {
            b.mxPresent(false).mxRecords(List.of());
            return false;
        }
    }

    // ── Risk + Summary ────────────────────────────────────────────────────────

    private String calculateRisk(DnsSecurityResult r) {
        // Consulta que não chegou não é registro ausente. Afirmar risco aqui
        // produziria o laudo que quebrou este scanner em produção: domínios com
        // SPF e DMARC corretos aparecendo como vulneráveis a spoofing.
        if (r.isLookupFailed()) return "UNKNOWN";

        // Registro que EXISTE mas é inválido (duplicado) não protege ninguém: o
        // receptor descarta. Para efeito de risco, equivale a não ter.
        boolean spfOk   = r.isSpfPresent()   && !"INVALID".equals(r.getSpfPolicy());
        boolean dmarcOk = r.isDmarcPresent() && !"INVALID".equals(r.getDmarcPolicy());

        if (!spfOk && !dmarcOk) {
            // Domínio sem MX não envia email por design — risco real existe mas é
            // menor que um domínio ativo sem proteção. HIGH é mais calibrado.
            return r.isMxPresent() ? "CRITICAL" : "HIGH";
        }
        if (!spfOk || !dmarcOk) return "HIGH";
        if ("STRONG".equals(r.getSpfPolicy()) && "STRONG".equals(r.getDmarcPolicy())) return "LOW";
        return "MEDIUM";
    }

    private String buildSummary(DnsSecurityResult r) {
        return switch (r.getEmailSpoofingRisk()) {
            case "CRITICAL" -> "Domínio sem SPF e sem DMARC — qualquer pessoa pode enviar emails falsos usando este domínio (spoofing).";
            case "HIGH"     -> "Configuração incompleta — risco de spoofing. Configure " +
                    (!r.isSpfPresent() ? "SPF" : "DMARC") + " para mitigar.";
            case "MEDIUM"   -> "Proteção parcial contra spoofing. Reforce SPF com -all e DMARC com p=reject para máxima proteção.";
            case "LOW"      -> "Boa configuração de segurança de email. SPF e DMARC configurados corretamente.";
            case "UNKNOWN"  -> "Não foi possível consultar o DNS deste domínio — os registros podem existir. "
                    + "Este resultado é inconclusivo, não um achado.";
            default         -> "Não foi possível determinar o risco.";
        };
    }
}
