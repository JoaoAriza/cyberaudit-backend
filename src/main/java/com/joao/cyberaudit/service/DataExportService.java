package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.Domain;
import com.joao.cyberaudit.model.ScheduledScan;
import com.joao.cyberaudit.repository.DomainRepository;
import com.joao.cyberaudit.repository.ScheduledScanRepository;
import org.springframework.stereotype.Service;

import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * LGPD Art. 18 — Portabilidade de dados.
 * Gera um mapa estruturado com todos os dados pessoais do usuário.
 */
@Service
public class DataExportService {

    private static final DateTimeFormatter FMT = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    private final DomainRepository       domainRepository;
    private final ScheduledScanRepository scheduledScanRepository;

    public DataExportService(DomainRepository domainRepository,
                             ScheduledScanRepository scheduledScanRepository) {
        this.domainRepository       = domainRepository;
        this.scheduledScanRepository = scheduledScanRepository;
    }

    /**
     * Coleta todos os dados pessoais associados ao usuário e retorna
     * como Map serializável para JSON.
     */
    public Map<String, Object> exportUserData(AppUser user) {
        Map<String, Object> export = new LinkedHashMap<>();
        export.put("exportedAt", java.time.LocalDateTime.now().format(FMT));
        export.put("lgpdBasis", "Art. 18 Lei 13.709/2018 — Portabilidade de Dados");

        // ── Perfil pessoal ────────────────────────────────────────────────────
        Map<String, Object> profile = new LinkedHashMap<>();
        profile.put("id",               user.getId().toString());
        profile.put("name",             user.getName());
        profile.put("email",            user.getEmail());
        profile.put("role",             user.getRole().name());
        profile.put("jobTitle",         user.getJobTitle());
        profile.put("country",          user.getCountry());
        profile.put("active",           user.isActive());
        profile.put("createdAt",        user.getCreatedAt() != null ? user.getCreatedAt().format(FMT) : null);
        profile.put("termsAccepted",    user.isTermsAccepted());
        profile.put("termsAcceptedAt",  user.getTermsAcceptedAt() != null ? user.getTermsAcceptedAt().format(FMT) : null);
        profile.put("totpEnabled",      user.isTotpEnabled());
        profile.put("emailOtpEnabled",  user.isEmailOtpEnabled());
        export.put("profile", profile);

        // ── Conta ─────────────────────────────────────────────────────────────
        if (user.getAccount() != null) {
            var acct = user.getAccount();
            Map<String, Object> account = new LinkedHashMap<>();
            account.put("id",          acct.getId().toString());
            account.put("type",        acct.getType() != null ? acct.getType().name() : null);
            account.put("plan",        acct.getPlan() != null ? acct.getPlan().name() : null);
            account.put("displayName", acct.getDisplayName());
            account.put("companyName", acct.getCompanyName());
            account.put("country",     acct.getCountry());
            account.put("createdAt",   acct.getCreatedAt() != null ? acct.getCreatedAt().format(FMT) : null);
            export.put("account", account);

            // ── Domínios da conta ─────────────────────────────────────────────
            List<Domain> domains = domainRepository.findByAccountOrderByCreatedAtDesc(acct);
            List<Map<String, Object>> domainList = domains.stream().map(d -> {
                Map<String, Object> dm = new LinkedHashMap<>();
                dm.put("host",       d.getHost());
                dm.put("verified",   d.isVerified());
                dm.put("createdAt",  d.getCreatedAt() != null ? d.getCreatedAt().format(FMT) : null);
                dm.put("verifiedAt", d.getVerifiedAt() != null ? d.getVerifiedAt().format(FMT) : null);
                return dm;
            }).toList();
            export.put("domains", domainList);
        }

        // ── Scans agendados do usuário ────────────────────────────────────────
        List<ScheduledScan> scans = scheduledScanRepository.findByUserOrderByCreatedAtDesc(user);
        List<Map<String, Object>> scanList = scans.stream().map(s -> {
            Map<String, Object> sm = new LinkedHashMap<>();
            sm.put("host",        s.getHost());
            sm.put("frequency",   s.getFrequency() != null ? s.getFrequency().name() : null);
            sm.put("active",      s.isActive());
            sm.put("notifyEmail", s.isNotifyEmail());
            sm.put("createdAt",   s.getCreatedAt() != null ? s.getCreatedAt().format(FMT) : null);
            sm.put("lastRun",     s.getLastRun() != null ? s.getLastRun().format(FMT) : null);
            return sm;
        }).toList();
        export.put("scheduledScans", scanList);

        return export;
    }
}
