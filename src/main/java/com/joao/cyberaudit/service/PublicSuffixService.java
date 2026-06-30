package com.joao.cyberaudit.service;

import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Resolve o domínio registrável (eTLD+1) usando a Public Suffix List oficial
 * (bundled em resources/public_suffix_list.dat). Exemplos:
 *   www.site.com.br   → site.com.br
 *   app.deep.site.com → site.com
 *   site.com.br       → site.com.br
 *   com.br            → null (é um public suffix)
 *
 * A lista é um snapshot (ver linha VERSION no .dat) e precisa de refresh periódico.
 */
@Service
public class PublicSuffixService {

    private final Set<String> normalRules    = new HashSet<>();
    private final Set<String> wildcardRules  = new HashSet<>(); // armazenado sem o prefixo "*."
    private final Set<String> exceptionRules = new HashSet<>(); // armazenado sem o prefixo "!"

    @PostConstruct
    void load() {
        try (InputStream in = getClass().getResourceAsStream("/public_suffix_list.dat")) {
            if (in == null) return; // sem PSL → registrableDomain degrada para eTLD+1 de 2 labels
            BufferedReader br = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("//")) continue;
                line = line.toLowerCase(Locale.ROOT);
                if (line.startsWith("!"))       exceptionRules.add(line.substring(1));
                else if (line.startsWith("*.")) wildcardRules.add(line.substring(2));
                else                             normalRules.add(line);
            }
        } catch (Exception ignored) {}
    }

    /**
     * Domínio registrável (eTLD+1) do host, ou null se o host for ele próprio um
     * public suffix ou não tiver um domínio registrável (ex: single-label).
     */
    public String registrableDomain(String host) {
        if (host == null) return null;
        String h = host.toLowerCase(Locale.ROOT).trim();
        while (h.endsWith(".")) h = h.substring(0, h.length() - 1);
        if (h.isEmpty() || !h.contains(".")) return null;

        String[] labels = h.split("\\.");
        int n = labels.length;

        int     psLabels          = 1;     // regra default "*": public suffix = 1 label (o TLD)
        boolean exception         = false;
        int     exceptionPsLabels = 0;

        for (int i = 0; i < n; i++) {
            int    len       = n - i;          // nº de labels do sufixo candidato
            String candidate = join(labels, i);

            if (exceptionRules.contains(candidate)) {
                // Exceção: public suffix = candidato menos o label mais à esquerda.
                exception = true;
                exceptionPsLabels = Math.max(exceptionPsLabels, len - 1);
            }
            if (normalRules.contains(candidate)) {
                psLabels = Math.max(psLabels, len);
            }
            // Wildcard "*.X": o 1º label é coringa, o resto (labels i+1..) deve ser regra wildcard.
            if (len >= 2 && wildcardRules.contains(join(labels, i + 1))) {
                psLabels = Math.max(psLabels, len);
            }
        }

        // Exceção tem prioridade sobre regras normais/wildcard (spec da PSL).
        int publicSuffixLabels = exception ? exceptionPsLabels : psLabels;
        int regLabels = publicSuffixLabels + 1;
        if (regLabels > n) return null;    // host é um public suffix → sem domínio registrável
        return join(labels, n - regLabels);
    }

    private static String join(String[] labels, int from) {
        StringBuilder sb = new StringBuilder();
        for (int i = from; i < labels.length; i++) {
            if (sb.length() > 0) sb.append('.');
            sb.append(labels[i]);
        }
        return sb.toString();
    }
}
