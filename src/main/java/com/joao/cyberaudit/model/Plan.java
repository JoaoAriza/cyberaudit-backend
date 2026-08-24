package com.joao.cyberaudit.model;

/**
 * Plano de assinatura da conta.
 *
 * Regras por tier:
 *  Guest  (sem login) — 5 scans/dia via GuestRateLimitService; sem módulos avançados
 *  FREE   (login)     — 10 scans/dia e nada mais: sem PDF, sem notificação por
 *                       e-mail, sem active scan, Changes, gráfico, agendamentos
 *                       ou cadastro de domínio
 *  PRO                — ilimitado, Changes, gráfico, agendamentos e domínios;
 *                       active scan, PDF e e-mail só em domínio verificado
 *  ENTERPRISE         — ilimitado + active scan + tudo, sem restrição de domínio
 *
 * Só a equipe da plataforma (PLATFORM_STAFF_EMAILS) recebe tratamento equivalente a
 * ENTERPRISE, conforme PlanLimitService.effectivePlan(AppUser). O role NÃO promove
 * plano: /auth/register cria todo cadastro como OWNER da própria conta.
 */
public enum Plan {
    //                 daily  sched  active  pdf    email  changes history domain reports
    FREE      (10,     0,     false, false,  false, false, false,  false, false),
    PRO       (-1,     10,    false, true,   true,  true,  true,   true,  true),
    ENTERPRISE(-1,     -1,    true,  true,   true,  true,  true,   true,  true);

    public final int     dailyScanLimit;      // -1 = ilimitado
    public final int     scheduledScanLimit;  // -1 = ilimitado
    public final boolean activeScanAllowed;
    /**
     * Exportar o laudo em PDF. O plano diz SE pode; PlanLimitService.checkPdfExport
     * diz SOBRE QUAL DOMÍNIO — o PRO pessoal só entrega sobre domínio verificado.
     */
    public final boolean pdfExportAllowed;
    /** Notificação por e-mail do scan concluído. Mesma regra de domínio do PDF. */
    public final boolean emailNotifyAllowed;
    public final boolean changesModuleAllowed;
    public final boolean historyChartAllowed;
    /** Cadastrar domínio próprio (e portanto verificá-lo) é PRO ou superior. */
    public final boolean domainRegistrationAllowed;
    /**
     * Relatórios da conta: log de auditoria, PDF executivo e página de status
     * pública. NÃO cobre gestão de equipe (usuários, convites, 2FA obrigatório),
     * que segue livre — uma conta COMPANY precisa montar o time antes de ter
     * motivo para assinar.
     */
    public final boolean reportsModuleAllowed;

    Plan(int dailyScanLimit, int scheduledScanLimit,
         boolean activeScanAllowed, boolean pdfExportAllowed, boolean emailNotifyAllowed,
         boolean changesModuleAllowed, boolean historyChartAllowed,
         boolean domainRegistrationAllowed, boolean reportsModuleAllowed) {
        this.dailyScanLimit            = dailyScanLimit;
        this.scheduledScanLimit        = scheduledScanLimit;
        this.activeScanAllowed         = activeScanAllowed;
        this.pdfExportAllowed          = pdfExportAllowed;
        this.emailNotifyAllowed        = emailNotifyAllowed;
        this.changesModuleAllowed      = changesModuleAllowed;
        this.historyChartAllowed       = historyChartAllowed;
        this.domainRegistrationAllowed = domainRegistrationAllowed;
        this.reportsModuleAllowed      = reportsModuleAllowed;
    }

    /** @return true se o plano não tem limite diário de scans */
    public boolean isUnlimited() { return dailyScanLimit < 0; }

    /**
     * Fronteira do "só no que é seu": scan ativo e entrega de laudo (PDF e e-mail)
     * valem apenas sobre domínio verificado da conta.
     *
     * Vale para o PRO pessoal. Conta COMPANY e ENTERPRISE não têm a restrição.
     *
     * Mora aqui porque a mesma expressão estava copiada em AccountDto e
     * PlanLimitService, e o catálogo de planos seria a terceira cópia — que é
     * exatamente o tipo de duplicação que deixou o cardápio mentir antes.
     */
    public boolean verifiedDomainOnly(boolean companyAccount) {
        return this == PRO && !companyAccount;
    }
}
