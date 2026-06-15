package com.joao.cyberaudit.model;

/**
 * Plano de assinatura da conta.
 *
 * Regras por tier:
 *  Guest  (sem login) — 5 scans/dia via GuestRateLimitService; sem módulos avançados
 *  FREE   (login)     — 10 scans/dia, PDF, sem active scan, sem Changes, sem gráfico
 *  PRO                — ilimitado, PDF, sem active scan, COM Changes e gráfico
 *  ENTERPRISE         — ilimitado + active scan + tudo
 *
 * OWNER e ADMIN recebem tratamento equivalente a ENTERPRISE independente do plano,
 * conforme lógica em PlanLimitService.effectivePlanForUser().
 */
public enum Plan {
    //                 daily  sched  active  pdf    changes history
    FREE      (10,     0,     false, true,   false, false),
    PRO       (-1,     10,    false, true,   true,  true),
    ENTERPRISE(-1,     -1,    true,  true,   true,  true);

    public final int     dailyScanLimit;      // -1 = ilimitado
    public final int     scheduledScanLimit;  // -1 = ilimitado
    public final boolean activeScanAllowed;
    public final boolean pdfExportAllowed;
    public final boolean changesModuleAllowed;
    public final boolean historyChartAllowed;

    Plan(int dailyScanLimit, int scheduledScanLimit,
         boolean activeScanAllowed, boolean pdfExportAllowed,
         boolean changesModuleAllowed, boolean historyChartAllowed) {
        this.dailyScanLimit        = dailyScanLimit;
        this.scheduledScanLimit    = scheduledScanLimit;
        this.activeScanAllowed     = activeScanAllowed;
        this.pdfExportAllowed      = pdfExportAllowed;
        this.changesModuleAllowed  = changesModuleAllowed;
        this.historyChartAllowed   = historyChartAllowed;
    }

    /** @return true se o plano não tem limite diário de scans */
    public boolean isUnlimited() { return dailyScanLimit < 0; }
}
