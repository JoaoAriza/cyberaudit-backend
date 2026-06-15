package com.joao.cyberaudit.dto;

import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.AccountType;
import com.joao.cyberaudit.model.Plan;
import com.joao.cyberaudit.util.CnpjUtil;
import lombok.Data;

import java.util.UUID;

@Data
public class AccountDto {

    private UUID id;
    private AccountType type;
    private Plan plan;
    private String displayName;
    private String companyName;
    private String country;
    /** CNPJ formatado (XX.XXX.XXX/XXXX-XX) — null para contas individuais */
    private String cnpj;

    /** Limites derivados do plano efetivo — podem ser sobrescritos para OWNER/ADMIN */
    private int     dailyScanLimit;
    private int     scheduledScanLimit;
    private boolean activeScanAllowed;
    private boolean pdfExportAllowed;
    private boolean changesModuleAllowed;
    private boolean historyChartAllowed;

    /** Constrói a partir da Account (usa plano da conta sem bypass de role). */
    public static AccountDto from(Account a) {
        return from(a, null);
    }

    /**
     * Constrói aplicando o plano efetivo.
     * Se effectivePlan != null, usa-o (bypass de OWNER/ADMIN aplicado pelo caller).
     */
    public static AccountDto from(Account a, Plan effectivePlan) {
        if (a == null) return null;
        Plan rawPlan  = a.getPlan() != null ? a.getPlan() : Plan.FREE;
        Plan usedPlan = effectivePlan != null ? effectivePlan : rawPlan;

        AccountDto dto = new AccountDto();
        dto.setId(a.getId());
        dto.setType(a.getType());
        dto.setPlan(rawPlan);            // plano real da conta
        dto.setDisplayName(a.getDisplayName());
        dto.setCompanyName(a.getCompanyName());
        dto.setCountry(a.getCountry());
        // Formata CNPJ se presente (armazenado como 14 dígitos)
        dto.setCnpj(a.getCnpj() != null ? CnpjUtil.format(a.getCnpj()) : null);
        // limites calculados do plano efetivo (pode ser ENTERPRISE para OWNER/ADMIN)
        dto.setDailyScanLimit(usedPlan.dailyScanLimit);
        dto.setScheduledScanLimit(usedPlan.scheduledScanLimit);
        dto.setActiveScanAllowed(usedPlan.activeScanAllowed);
        dto.setPdfExportAllowed(usedPlan.pdfExportAllowed);
        dto.setChangesModuleAllowed(usedPlan.changesModuleAllowed);
        dto.setHistoryChartAllowed(usedPlan.historyChartAllowed);
        return dto;
    }
}