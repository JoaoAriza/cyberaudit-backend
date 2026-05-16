package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.DnsSecurityResult;
import org.springframework.stereotype.Service;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.MXRecord;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class DnsSecurityService {

    private static final List<String> DKIM_SELECTORS = List.of(
            "default", "google", "mail", "dkim",
            "k1", "s1", "s2", "email", "selector1", "selector2"
    );

    // Extrai o valor de p= sem confundir com sp=
    private static final Pattern DMARC_P = Pattern.compile(
            "(?:^|;)\\s*p=([^;\\s]+)", Pattern.CASE_INSENSITIVE
    );

    public DnsSecurityResult scan(String host) {
        DnsSecurityResult.DnsSecurityResultBuilder b = DnsSecurityResult.builder();

        try {
            analyzeSpf(host, b);
            analyzeDmarc(host, b);
            analyzeDkim(host, b);
            analyzeCaa(host, b);
            analyzeMx(host, b);
        } catch (Exception e) {
            b.summary("Erro ao consultar DNS: " + e.getMessage());
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

                // Monta a string completa concatenando todas as partes do TXT
                StringBuilder sb = new StringBuilder();
                for (String part : txt.getStrings()) sb.append(part);
                String content = sb.toString().trim();

                // Verificação case-insensitive e com trim
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

                // Extrai o valor de p= com regex para evitar confundir com sp=
                Matcher m = DMARC_P.matcher(content);
                if (m.find()) {
                    String pValue = m.group(1).toLowerCase().trim();
                    switch (pValue) {
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

    // ── DKIM ──────────────────────────────────────────────────────────────────

    private void analyzeDkim(String host,
                             DnsSecurityResult.DnsSecurityResultBuilder b) {
        for (String selector : DKIM_SELECTORS) {
            try {
                org.xbill.DNS.Record[] records =
                        new Lookup(selector + "._domainkey." + host, Type.TXT).run();
                if (records != null && records.length > 0) {
                    b.dkimHintFound(true).dkimSelector(selector);
                    return;
                }
            } catch (Exception ignored) {}
        }
        b.dkimHintFound(false).dkimSelector(null);
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
        boolean spfStrong   = "STRONG".equals(r.getSpfPolicy());
        boolean spfPresent  = r.isSpfPresent();
        boolean dmarcStrong = "STRONG".equals(r.getDmarcPolicy());
        boolean dmarcPresent= r.isDmarcPresent();

        if (!spfPresent && !dmarcPresent)  return "CRITICAL";
        if (!spfPresent || !dmarcPresent)  return "HIGH";
        if (spfStrong && dmarcStrong)      return "LOW";
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