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
    private org.xbill.DNS.Record[] consultar(String nome, int tipo, AtomicBoolean falhou) {
        try {
            Lookup lookup = new Lookup(nome, tipo);
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

    public DnsSecurityResult scan(String host) {
        DnsSecurityResult.DnsSecurityResultBuilder b = DnsSecurityResult.builder();
        // Por execução e compartilhado entre as cinco análises paralelas:
        // qualquer uma delas pode ser a que não conseguiu perguntar.
        AtomicBoolean falhou = new AtomicBoolean(false);
        ExecutorService pool = Executors.newFixedThreadPool(5);
        try {
            var spfFuture   = CompletableFuture.runAsync(() -> analyzeSpf(host, falhou, b),   pool);
            var dmarcFuture = CompletableFuture.runAsync(() -> analyzeDmarc(host, falhou, b), pool);
            var dkimFuture  = CompletableFuture.runAsync(() -> analyzeDkim(host, falhou, b),  pool);
            var caaFuture   = CompletableFuture.runAsync(() -> analyzeCaa(host, falhou, b),   pool);
            var mxFuture    = CompletableFuture.runAsync(() -> analyzeMx(host, falhou, b),    pool);

            CompletableFuture.allOf(spfFuture, dmarcFuture, dkimFuture, caaFuture, mxFuture)
                    .get(8, TimeUnit.SECONDS);

        } catch (Exception e) {
            falhou.set(true);
            b.summary("Erro ao consultar DNS: " + e.getMessage());
        } finally {
            pool.shutdownNow();
        }

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
            org.xbill.DNS.Record[] records = consultar(domain, Type.TXT, falhou);
            if (records == null) { b.spfPresent(false).spfPolicy("MISSING"); return false; }

            for (org.xbill.DNS.Record r : records) {
                if (!(r instanceof TXTRecord txt)) continue;

                StringBuilder sb = new StringBuilder();
                for (String part : txt.getStrings()) sb.append(part);
                String content = sb.toString().trim();

                if (!content.toLowerCase().startsWith("v=spf1")) continue;

                b.spfPresent(true).spfRecord(content);
                if      (content.contains("-all")) b.spfPolicy("STRONG");
                else if (content.contains("~all")) b.spfPolicy("MEDIUM");
                else if (content.contains("+all") || content.contains("?all")) b.spfPolicy("WEAK");
                else                               b.spfPolicy("MEDIUM");
                return true;
            }
            b.spfPresent(false).spfPolicy("MISSING");
            return false;
        } catch (Exception e) {
            b.spfPresent(false).spfPolicy("MISSING");
            return false;
        }
    }

    // ── DMARC ─────────────────────────────────────────────────────────────────

    private void analyzeDmarc(String host, AtomicBoolean falhou,
                              DnsSecurityResult.DnsSecurityResultBuilder b) {
        // RFC 7489 §6.6.3: receivers fall back to org domain if subdomain has no record.
        // We mirror this: try the host first, then the parent domain.
        if (queryDmarc(host, falhou, b)) return;

        String parent = publicSuffixService.registrableDomain(host);
        if (parent != null && !parent.equals(host)) {
            queryDmarc(parent, falhou, b);
        }
        // queryDmarc sets MISSING if nothing was found
    }

    /**
     * Queries _dmarc.<domain> and populates the builder.
     * @return true if a valid DMARC record was found and parsed
     */
    private boolean queryDmarc(String domain, AtomicBoolean falhou,
                               DnsSecurityResult.DnsSecurityResultBuilder b) {
        try {
            org.xbill.DNS.Record[] records = consultar("_dmarc." + domain, Type.TXT, falhou);
            if (records == null) { b.dmarcPresent(false).dmarcPolicy("MISSING"); return false; }

            for (org.xbill.DNS.Record r : records) {
                if (!(r instanceof TXTRecord txt)) continue;

                StringBuilder sb = new StringBuilder();
                for (String part : txt.getStrings()) sb.append(part);
                String content = sb.toString().trim();

                if (!content.startsWith("v=DMARC1")) continue;

                b.dmarcPresent(true).dmarcRecord(content);

                Matcher m = DMARC_P.matcher(content);
                if (m.find()) {
                    switch (m.group(1).toLowerCase().trim()) {
                        case "reject"     -> b.dmarcPolicy("STRONG");
                        case "quarantine" -> b.dmarcPolicy("MEDIUM");
                        default           -> b.dmarcPolicy("WEAK");
                    }
                } else {
                    b.dmarcPolicy("WEAK");
                }
                return true;
            }
        } catch (Exception ignored) {}
        b.dmarcPresent(false).dmarcPolicy("MISSING");
        return false;
    }

    // ── DKIM — seletores testados em paralelo ─────────────────────────────────

    private void analyzeDkim(String host, AtomicBoolean falhou,
                             DnsSecurityResult.DnsSecurityResultBuilder b) {
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

        // Cap de 20 threads — DNS é rápido e os lookups rodam em paralelo
        int poolSize = Math.min(Math.max(probes.size(), 1), 20);
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
                    .get(5, TimeUnit.SECONDS);

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

    private void analyzeCaa(String host, AtomicBoolean falhou,
                            DnsSecurityResult.DnsSecurityResultBuilder b) {
        try {
            org.xbill.DNS.Record[] records = consultar(host, Type.CAA, falhou);
            if (records == null || records.length == 0) { b.caaPresent(false); return; }
            b.caaPresent(true).caaRecord(records[0].toString());
        } catch (Exception e) {
            b.caaPresent(false);
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

        if (!r.isSpfPresent() && !r.isDmarcPresent()) {
            // Domínio sem MX não envia email por design — risco real existe mas é
            // menor que um domínio ativo sem proteção. HIGH é mais calibrado.
            return r.isMxPresent() ? "CRITICAL" : "HIGH";
        }
        if (!r.isSpfPresent() || !r.isDmarcPresent()) return "HIGH";
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
