package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.DnsSecurityResult;
import org.springframework.stereotype.Service;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.MXRecord;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Service
public class DnsSecurityService {

    /**
     * Seletores DKIM conhecidos por provider.
     *
     * Problema anterior: lista com apenas 10 seletores genéricos — seletores de
     * providers como SendGrid (em), Proton (protonmail), Zoho (zoho), Amazon SES
     * (amazonses), FastMail (fm1/fm2/fm3), HubSpot (hubspot1) não eram checados,
     * resultando em "DKIM não detectado" mesmo quando DKIM estava corretamente
     * configurado. Isso tornava o relatório impreciso e confundia o usuário.
     *
     * Todos os lookups são paralelos — adicionar mais seletores não aumenta latência.
     * Timeout total: 5s (já existente).
     *
     * Nota: seletores baseados em data (ex: Google "20161025") não são adivinháveis
     * sem consultar o DNS por wildcard (não suportado). Se nenhum seletor for encontrado
     * o resultado é marcado como NOT_DETECTED (inconclusivo), não MISSING.
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

    private final PublicSuffixService publicSuffixService;

    public DnsSecurityService(PublicSuffixService publicSuffixService) {
        this.publicSuffixService = publicSuffixService;
    }

    public DnsSecurityResult scan(String host) {
        DnsSecurityResult.DnsSecurityResultBuilder b = DnsSecurityResult.builder();
        ExecutorService pool = Executors.newFixedThreadPool(5);
        try {
            var spfFuture   = CompletableFuture.runAsync(() -> analyzeSpf(host, b),   pool);
            var dmarcFuture = CompletableFuture.runAsync(() -> analyzeDmarc(host, b), pool);
            var dkimFuture  = CompletableFuture.runAsync(() -> analyzeDkim(host, b),  pool);
            var caaFuture   = CompletableFuture.runAsync(() -> analyzeCaa(host, b),   pool);
            var mxFuture    = CompletableFuture.runAsync(() -> analyzeMx(host, b),    pool);

            CompletableFuture.allOf(spfFuture, dmarcFuture, dkimFuture, caaFuture, mxFuture)
                    .get(8, TimeUnit.SECONDS);

        } catch (Exception e) {
            b.summary("Erro ao consultar DNS: " + e.getMessage());
        } finally {
            pool.shutdownNow();
        }

        DnsSecurityResult result = b.build();
        result.setEmailSpoofingRisk(calculateRisk(result));
        result.setSummary(buildSummary(result));
        return result;
    }

    // ── SPF ───────────────────────────────────────────────────────────────────

    private void analyzeSpf(String host,
                            DnsSecurityResult.DnsSecurityResultBuilder b) {
        // SPF é propriedade do domínio organizacional (apex). Ao escanear um
        // subdomínio (ex: www.site.com), o SPF normalmente está no apex (site.com).
        // Espelha o fallback do DMARC: tenta o host, depois o domínio pai.
        if (querySpf(host, b)) return;

        String parent = publicSuffixService.registrableDomain(host);
        if (parent != null && !parent.equals(host)) {
            querySpf(parent, b);
        }
        // querySpf marca MISSING se nada for encontrado
    }

    /**
     * Consulta SPF no domínio dado e popula o builder.
     * @return true se um registro v=spf1 válido foi encontrado
     */
    private boolean querySpf(String domain,
                             DnsSecurityResult.DnsSecurityResultBuilder b) {
        try {
            org.xbill.DNS.Record[] records = new Lookup(domain, Type.TXT).run();
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

    private void analyzeDmarc(String host,
                              DnsSecurityResult.DnsSecurityResultBuilder b) {
        // RFC 7489 §6.6.3: receivers fall back to org domain if subdomain has no record.
        // We mirror this: try the host first, then the parent domain.
        if (queryDmarc(host, b)) return;

        String parent = publicSuffixService.registrableDomain(host);
        if (parent != null && !parent.equals(host)) {
            queryDmarc(parent, b);
        }
        // queryDmarc sets MISSING if nothing was found
    }

    /**
     * Queries _dmarc.<domain> and populates the builder.
     * @return true if a valid DMARC record was found and parsed
     */
    private boolean queryDmarc(String domain,
                               DnsSecurityResult.DnsSecurityResultBuilder b) {
        try {
            org.xbill.DNS.Record[] records = new Lookup("_dmarc." + domain, Type.TXT).run();
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

    private void analyzeDkim(String host,
                             DnsSecurityResult.DnsSecurityResultBuilder b) {
        // Probe os seletores no host E no apex (mesmo motivo de SPF/MX): DKIM costuma
        // estar publicado em selector._domainkey.<apex>. Combina os dois domínios em
        // um único batch paralelo para não dobrar a latência.
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
                                    new Lookup(p[0] + "._domainkey." + p[1], Type.TXT).run();
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

    private void analyzeCaa(String host,
                            DnsSecurityResult.DnsSecurityResultBuilder b) {
        try {
            org.xbill.DNS.Record[] records = new Lookup(host, Type.CAA).run();
            if (records == null || records.length == 0) { b.caaPresent(false); return; }
            b.caaPresent(true).caaRecord(records[0].toString());
        } catch (Exception e) {
            b.caaPresent(false);
        }
    }

    // ── MX ────────────────────────────────────────────────────────────────────

    private void analyzeMx(String host,
                           DnsSecurityResult.DnsSecurityResultBuilder b) {
        // MX normalmente fica no apex. Mesmo fallback de SPF/DMARC para não reportar
        // "sem MX" (e elevar o risco indevidamente) quando se escaneia um subdomínio.
        if (queryMx(host, b)) return;

        String parent = publicSuffixService.registrableDomain(host);
        if (parent != null && !parent.equals(host)) {
            queryMx(parent, b);
        }
    }

    /**
     * Consulta MX no domínio dado e popula o builder.
     * @return true se ao menos um registro MX foi encontrado
     */
    private boolean queryMx(String domain,
                            DnsSecurityResult.DnsSecurityResultBuilder b) {
        try {
            org.xbill.DNS.Record[] records = new Lookup(domain, Type.MX).run();
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
            default         -> "Não foi possível determinar o risco.";
        };
    }
}
