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

    private static final List<String> DKIM_SELECTORS = List.of(
            "default", "google", "mail", "dkim",
            "k1", "s1", "s2", "email", "selector1", "selector2"
    );

    private static final Pattern DMARC_P = Pattern.compile(
            "(?:^|;)\\s*p=([^;\\s]+)", Pattern.CASE_INSENSITIVE
    );

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
        try {
            org.xbill.DNS.Record[] records = new Lookup(host, Type.TXT).run();
            if (records == null) { b.spfPresent(false).spfPolicy("MISSING"); return; }

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
                return;
            }
            b.spfPresent(false).spfPolicy("MISSING");
        } catch (Exception e) {
            b.spfPresent(false).spfPolicy("MISSING");
        }
    }

    // ── DMARC ─────────────────────────────────────────────────────────────────

    private void analyzeDmarc(String host,
                              DnsSecurityResult.DnsSecurityResultBuilder b) {
        try {
            org.xbill.DNS.Record[] records = new Lookup("_dmarc." + host, Type.TXT).run();
            if (records == null) { b.dmarcPresent(false).dmarcPolicy("MISSING"); return; }

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
                return;
            }
            b.dmarcPresent(false).dmarcPolicy("MISSING");
        } catch (Exception e) {
            b.dmarcPresent(false).dmarcPolicy("MISSING");
        }
    }

    // ── DKIM — seletores testados em paralelo ─────────────────────────────────

    private void analyzeDkim(String host,
                             DnsSecurityResult.DnsSecurityResultBuilder b) {
        ExecutorService pool = Executors.newFixedThreadPool(DKIM_SELECTORS.size());
        try {
            List<CompletableFuture<String>> futures = DKIM_SELECTORS.stream()
                    .map(selector -> CompletableFuture.supplyAsync(() -> {
                        try {
                            org.xbill.DNS.Record[] records =
                                    new Lookup(selector + "._domainkey." + host, Type.TXT).run();
                            return (records != null && records.length > 0) ? selector : null;
                        } catch (Exception e) { return null; }
                    }, pool))
                    .toList();

            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                    .get(5, TimeUnit.SECONDS);

            futures.stream()
                    .map(f -> f.getNow(null))
                    .filter(Objects::nonNull)
                    .findFirst()
                    .ifPresentOrElse(
                            sel -> b.dkimHintFound(true).dkimSelector(sel),
                            ()  -> b.dkimHintFound(false).dkimSelector(null)
                    );
        } catch (Exception e) {
            b.dkimHintFound(false).dkimSelector(null);
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
        try {
            org.xbill.DNS.Record[] records = new Lookup(host, Type.MX).run();
            if (records == null || records.length == 0) {
                b.mxPresent(false).mxRecords(List.of());
                return;
            }
            List<String> mx = new ArrayList<>();
            for (org.xbill.DNS.Record r : records) {
                if (r instanceof MXRecord mxr)
                    mx.add(mxr.getPriority() + " " + mxr.getTarget());
            }
            b.mxPresent(true).mxRecords(mx);
        } catch (Exception e) {
            b.mxPresent(false).mxRecords(List.of());
        }
    }

    // ── Risk + Summary ────────────────────────────────────────────────────────

    private String calculateRisk(DnsSecurityResult r) {
        if (!r.isSpfPresent() && !r.isDmarcPresent()) return "CRITICAL";
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
