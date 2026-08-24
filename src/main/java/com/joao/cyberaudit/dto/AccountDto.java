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

    /** 2FA obrigatório configurado pelo OWNER */
    private boolean require2fa;

    /** Limites derivados do plano efetivo — podem ser sobrescritos para OWNER/ADMIN */
    private int     dailyScanLimit;
    private int     scheduledScanLimit;
    private boolean activeScanAllowed;
    /** true = PRO INDIVIDUAL — scan ativo permitido apenas em domínios verificados */
    private boolean activeScanOnVerifiedOnly;
    private boolean pdfExportAllowed;
    /** Notificação por e-mail do scan concluído — PRO+ */
    private boolean emailNotifyAllowed;
    /**
     * true = PRO PESSOAL — PDF e e-mail só sobre domínios verificados da conta.
     * O laudo exportável é o entregável do produto: sem prova de posse, a
     * assinatura pessoal viraria gerador de auditoria de site alheio.
     */
    private boolean reportOnVerifiedOnly;
    private boolean changesModuleAllowed;
    private boolean historyChartAllowed;
    /** Cadastrar domínio próprio — PRO ou superior */
    private boolean domainRegistrationAllowed;
    /** Relatórios da conta (auditoria, PDF executivo, página de status) — PRO+ */
    private boolean reportsModuleAllowed;

    /** Token para a página de status pública — null = desativada */
    private String publicStatusToken;

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
        dto.setRequire2fa(a.isRequire2fa());
        // limites calculados do plano efetivo (pode ser ENTERPRISE para OWNER/ADMIN)
        boolean isCompany = a.getType() == AccountType.COMPANY;
        // PRO pode fazer active scan em domínios verificados; COMPANY/ENTERPRISE pode em qualquer
        boolean canActiveScan = usedPlan.activeScanAllowed || usedPlan == Plan.PRO;
        boolean verifiedOnly  = usedPlan.verifiedDomainOnly(isCompany);

        dto.setDailyScanLimit(usedPlan.dailyScanLimit);
        dto.setScheduledScanLimit(usedPlan.scheduledScanLimit);
        dto.setActiveScanAllowed(canActiveScan);
        dto.setActiveScanOnVerifiedOnly(verifiedOnly);
        dto.setPdfExportAllowed(usedPlan.pdfExportAllowed);
        dto.setEmailNotifyAllowed(usedPlan.emailNotifyAllowed);
        // Mesma fronteira do active scan: PRO pessoal entrega só sobre o que é dele.
        dto.setReportOnVerifiedOnly(verifiedOnly);
        dto.setChangesModuleAllowed(usedPlan.changesModuleAllowed);
        dto.setHistoryChartAllowed(usedPlan.historyChartAllowed);
        dto.setDomainRegistrationAllowed(usedPlan.domainRegistrationAllowed);
        dto.setReportsModuleAllowed(usedPlan.reportsModuleAllowed);
        dto.setPublicStatusToken(a.getPublicStatusToken());
        return dto;
    }
}