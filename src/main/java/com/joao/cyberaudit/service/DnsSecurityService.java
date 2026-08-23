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
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
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

        // ── Fase 1: o que decide o risco ──────────────────────────────────
        ExecutorService pool = Executors.newFixedThreadPool(4);
        try {
            var spfFuture   = CompletableFuture.runAsync(() -> analyzeSpf(host, falhou, b),   pool);
            var dmarcFuture = CompletableFuture.runAsync(() -> analyzeDmarc(host, falhou, b), pool);
            var caaFuture   = CompletableFuture.runAsync(() -> analyzeCaa(host, falhou, b),   pool);
            var mxFuture    = CompletableFuture.runAsync(() -> analyzeMx(host, falhou, b),    pool);

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
        analyzeDkim(host, b);

        b.lookupFailed(falhou.get());
        DnsSecurityResult result = b.build();
        result.setEmailSpoofingRisk(calculateRisk(result));
        result.setSummary(buildSummary(result));
        return result;
    }

    // ── SPF ───────────────────────────────────────────────────────────────────

    private void analyzeSpf(String host, AtomicBoolean falhou,
                            DnsSecurityResult.DnsSecurityResultBuilder b) {
        // SPF normalmente fica no apex. Tenta o host, depois o domínio registrável (apex).
        if (querySpf(host, falhou, b)) return;

        String parent = publicSuffixService.registrableDomain(host);
        if (parent != null && !parent.equals(host)) {
            querySpf(parent, falhou, b);
        }
        // querySpf marca MISSING se nada for encontrado
    }

    /**
     * Consulta SPF no domínio dado e popula o builder.
     * @return true se um registro v=spf1 válido foi encontrado
     */
    private boolean querySpf(String domain, AtomicBoolean falhou,
                             DnsSecurityResult.DnsSecurityResultBuilder b) {
        try {
            List<String> spfs = textosQueComecamCom(
                    consultar(domain, Type.TXT, falhou), "v=spf1");

            if (spfs.isEmpty()) { b.spfPresent(false).spfPolicy("MISSING"); return false; }

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
     * O DKIM sonda ~40 seletores em 2 domínios: mais de 80 consultas especulativas
     * de uma vez, contra nomes que na maioria não existem.
     *
     * Por isso ele NÃO alimenta o sinal de falha global. Se algumas dessas sondas
     * estouram o tempo — o que é esperado num lote grande, ainda mais em instância
     * com CPU limitada —, isso não diz nada sobre a saúde do DNS: o SPF e o DMARC
     * podem ter resolvido perfeitamente em uma consulta cada.
     *
     * Deixar o lote de DKIM marcar falha global fazia o resultado inteiro virar
     * UNKNOWN por causa da parte mais especulativa da análise. O DKIM já tem seu
     * próprio estado honesto para isso: NOT_DETECTED.
     */
    private void analyzeDkim(String host,
                             DnsSecurityResult.DnsSecurityResultBuilder b) {
        // Isolado do sinal global: ver javadoc acima.
        AtomicBoolean falhou = new AtomicBoolean(false);
        // Proba os seletores no host e no apex (DKIM costuma estar em
        // selector._domainkey.<apex>), num único batch paralelo.
        List<String> domains = new ArrayList<>();
        domains.add(host);
        String parent = publicSuffixService.registrableDomain(host);
        if (parent != null && !parent.equals(host)) domains.add(parent);

        List<String[]> probes = new ArrayList<>();   // {selector, domain}
        for (String domain : domains)
            for (String selector : DKIM_SELECTORS)
                probes.add(new String[]{ selector, domain });

        // Concorrência baixa de propósito: 20 threads disparando 84 consultas de
        // uma vez saturavam o cliente HTTP (no modo DoH, cada uma é uma requisição)
        // e derrubavam por timeout até as consultas de SPF e DMARC. Adivinhar
        // seletor não justifica atrapalhar o que decide o veredito.
        int poolSize = Math.min(Math.max(probes.size(), 1), 4);
        ExecutorService pool = Executors.newFixedThreadPool(poolSize);
        try {
            List<CompletableFuture<String>> futures = probes.stream()
                    .map(p -> CompletableFuture.supplyAsync(() -> {
                        try {
                            org.xbill.DNS.Record[] records =
                                    consultar(p[0] + "._domainkey." + p[1], Type.TXT, falhou);
                            return (records != null && records.length > 0) ? p[0] : null;
                        } catch (Exception e) { return null; }
                    }, pool))
                    .toList();

            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                    .get(8, TimeUnit.SECONDS);

            List<String> found = futures.stream()
                    .map(f -> f.getNow(null))
                    .filter(Objects::nonNull)
                    .collect(Collectors.toList());

            if (!found.isEmpty()) {
                // Seletor confirmado
                b.dkimHintFound(true).dkimSelector(found.get(0));
            } else {
                // Nenhum seletor da lista respondeu.
                // Isso NÃO significa ausência de DKIM — o domínio pode usar seletores
                // customizados ou baseados em data (ex: Google "20230601") que não são
                // adivinháveis sem enumeração. Marcamos como NOT_DETECTED (inconclusivo).
                b.dkimHintFound(false).dkimSelector("NOT_DETECTED");
            }
        } catch (Exception e) {
            b.dkimHintFound(false).dkimSelector("NOT_DETECTED");
        } finally {
            pool.shutdownNow();
        }
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
            b.caaPresent(true).caaRecord(records[0].toString());
            return true;
        } catch (Exception e) {
            b.caaPresent(false);
            return false;
        }
    }

    // ── MX ────────────────────────────────────────────────────────────────────

    private void analyzeMx(String host, AtomicBoolean falhou,
                           DnsSecurityResult.DnsSecurityResultBuilder b) {
        // MX normalmente fica no apex. Tenta o host, depois o domínio registrável (apex).
        if (queryMx(host, falhou, b)) return;

        String parent = publicSuffixService.registrableDomain(host);
        if (parent != null && !parent.equals(host)) {
            queryMx(parent, falhou, b);
        }
    }

    /**
     * Consulta MX no domínio dado e popula o builder.
     * @return true se ao menos um registro MX foi encontrado
     */
    private boolean queryMx(String domain, AtomicBoolean falhou,
                            DnsSecurityResult.DnsSecurityResultBuilder b) {
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
