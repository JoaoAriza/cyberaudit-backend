package com.joao.cyberaudit.service;

import com.joao.cyberaudit.exception.EmailDeliveryException;
import com.joao.cyberaudit.model.Feedback;
import com.joao.cyberaudit.model.ScanResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    private final EmailSender emailSender;

    @Value("${mail.enabled:false}")
    private boolean enabled;

    @Value("${mail.from:noreply@cyberaudit.app}")
    private String from;

    public EmailService(EmailSender emailSender) {
        this.emailSender = emailSender;
    }

    /**
     * Envia email de conclusão de scan para o usuário autenticado.
     * Silenciosamente ignorado se mail.enabled=false ou se o envio falhar.
     */
    public void sendScanComplete(String toEmail, String toName, ScanResult result) {
        if (!enabled || toEmail == null || toEmail.isBlank()) return;

        try {
            String host  = result.getUrl() != null ? result.getUrl() : "—";
            int    score = result.getScore() != null ? result.getScore().getScore() : 0;
            String risk  = result.getScore() != null ? result.getScore().getRiskLevel().name() : "UNKNOWN";
            String color = riskColor(risk);

            String subject = "CyberAudit — Scan concluído: " + host + " (" + score + "/100)";
            String html    = buildHtml(toName, host, score, risk, color, result);

            emailSender.send(from, toEmail, subject, html);

        } catch (RuntimeException e) {
            // Não propaga — falha de email nunca deve derrubar o scan
            System.err.println("[EmailService] Falha ao enviar notificação: " + e.getMessage());
        }
    }

    /**
     * Envia alerta de degradação de score de segurança ao OWNER/ADMIN da conta.
     */
    public void sendDegradationAlert(String toEmail, String toName, String host,
                                     int oldScore, int newScore, String newRisk,
                                     String reason, ScanResult result) {
        if (!enabled || toEmail == null || toEmail.isBlank()) return;
        try {
            String firstName = toName != null && toName.contains(" ")
                    ? toName.substring(0, toName.indexOf(' ')) : (toName != null ? toName : "usuário");
            int    drop      = oldScore - newScore;
            String color     = riskColor(newRisk);

            StringBuilder findings = new StringBuilder();
            if (result.getScore() != null && result.getScore().getIssues() != null) {
                result.getScore().getIssues().stream()
                        .filter(i -> "CRITICAL".equals(i.getSeverity()) || "HIGH".equals(i.getSeverity()))
                        .limit(5)
                        .forEach(issue -> {
                            String sev      = issue.getSeverity() != null ? issue.getSeverity() : "INFO";
                            String sevColor = switch (sev) {
                                case "CRITICAL" -> "#ff4040";
                                case "HIGH"     -> "#ff6b35";
                                default         -> "#f5a623";
                            };
                            findings.append("""
                                <tr>
                                  <td style="padding:5px 0;border-bottom:1px solid #1c2a3a;">
                                    <span style="display:inline-block;padding:2px 7px;border-radius:3px;
                                          font-size:10px;font-weight:700;color:%s;border:1px solid %s;
                                          font-family:monospace;">%s</span>
                                  </td>
                                  <td style="padding:5px 8px;border-bottom:1px solid #1c2a3a;
                                        color:#b8ccde;font-size:13px;">%s</td>
                                </tr>
                                """.formatted(sevColor, sevColor, sev,
                                    escHtml(issue.getTitle() != null ? issue.getTitle() : issue.getId())));
                        });
            }
            String findingsSection = findings.length() > 0
                    ? "<p style='margin:0 0 6px;font-size:11px;color:#5a7a96;text-transform:uppercase;letter-spacing:.08em;'>Issues críticos/altos</p>"
                      + "<table width='100%' cellpadding='0' cellspacing='0'>" + findings + "</table>"
                    : "";

            String html = """
                <!DOCTYPE html><html lang="pt-BR">
                <body style="margin:0;padding:0;background:#0a1520;font-family:'Segoe UI',Arial,sans-serif;">
                  <table width="100%%" cellpadding="0" cellspacing="0" style="background:#0a1520;padding:32px 16px;">
                    <tr><td align="center">
                      <table width="560" cellpadding="0" cellspacing="0"
                             style="background:#0d1b2a;border:1px solid #1c2a3a;border-radius:8px;overflow:hidden;">
                        <tr><td style="background:#0a1520;padding:20px 28px;border-bottom:3px solid #ff4040;">
                          <span style="font-size:20px;font-weight:700;color:#00d4a0;letter-spacing:.05em;">◈ CyberAudit</span>
                          <span style="margin-left:16px;font-size:12px;color:#ff4040;font-weight:700;letter-spacing:.08em;">⚠ ALERTA DE DEGRADAÇÃO</span>
                        </td></tr>
                        <tr><td style="padding:28px;">
                          <p style="margin:0 0 16px;color:#b8ccde;font-size:15px;">
                            Olá, <strong style="color:#e0eaf4;">%s</strong>.
                          </p>
                          <p style="margin:0 0 20px;color:#5a7a96;font-size:14px;">
                            O score de segurança do domínio abaixo piorou significativamente:
                          </p>
                          <table width="100%%" cellpadding="0" cellspacing="0"
                                 style="background:#0a1520;border:1px solid #ff4040;border-radius:6px;margin-bottom:20px;">
                            <tr><td style="padding:20px 24px;">
                              <div style="font-size:12px;color:#5a7a96;text-transform:uppercase;
                                          letter-spacing:.08em;margin-bottom:4px;">Domínio</div>
                              <div style="font-size:17px;font-weight:600;color:#e0eaf4;
                                          font-family:monospace;margin-bottom:16px;">%s</div>
                              <table cellpadding="0" cellspacing="0">
                                <tr>
                                  <td style="padding-right:28px;">
                                    <div style="font-size:11px;color:#5a7a96;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px;">Score anterior</div>
                                    <div style="font-size:24px;font-weight:700;color:#5a7a96;">%d<span style="font-size:12px;">/100</span></div>
                                  </td>
                                  <td style="padding-right:28px;">
                                    <div style="font-size:18px;color:#ff4040;font-weight:700;">▼ %d</div>
                                  </td>
                                  <td style="padding-right:28px;">
                                    <div style="font-size:11px;color:#5a7a96;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px;">Score atual</div>
                                    <div style="font-size:24px;font-weight:700;color:%s;">%d<span style="font-size:12px;">/100</span></div>
                                  </td>
                                  <td>
                                    <div style="font-size:11px;color:#5a7a96;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px;">Risco</div>
                                    <div style="display:inline-block;padding:4px 10px;border-radius:4px;
                                                font-size:12px;font-weight:700;color:%s;border:1px solid %s;">%s</div>
                                  </td>
                                </tr>
                              </table>
                            </td></tr>
                          </table>
                          <p style="margin:0 0 16px;color:#b8ccde;font-size:13px;"><strong>Motivo:</strong> %s</p>
                          %s
                          <p style="margin:24px 0 0;text-align:center;">
                            <a href="https://cyberaudit.app"
                               style="display:inline-block;padding:11px 28px;background:#ff4040;
                                      color:#fff;font-weight:700;font-size:14px;border-radius:5px;
                                      text-decoration:none;">
                              Ver relatório completo →
                            </a>
                          </p>
                        </td></tr>
                        <tr><td style="padding:16px 28px;border-top:1px solid #1c2a3a;
                                       color:#344d62;font-size:11px;text-align:center;">
                          Você recebeu este alerta como administrador do CyberAudit.
                        </td></tr>
                      </table>
                    </td></tr>
                  </table>
                </body></html>
                """.formatted(escHtml(firstName), escHtml(host), oldScore, drop, color, newScore,
                              color, color, newRisk, escHtml(reason), findingsSection);

            emailSender.send(from, toEmail, "⚠ CyberAudit — Degradação detectada: " + host + " (" + oldScore + " → " + newScore + ")", html);
        } catch (Exception e) {
            System.err.println("[EmailService] Falha ao enviar alerta de degradação: " + e.getMessage());
        }
    }

    /**
     * Envia o código OTP de 6 dígitos para verificação 2FA via email.
     */
    /**
     * Envia o código 2FA. Diferente dos outros e-mails desta classe, NÃO engole
     * falha: ver {@link EmailDeliveryException} para o porquê.
     */
    public void sendOtpEmail(String toEmail, String toName, String code) {
        sendOtpEmail(toEmail, toName, code, false);
    }

    /**
     * @param ativacao true quando o código confirma a ativação do 2FA, false no login.
     *
     * O assunto e o texto mudam por um motivo prático: só um código vale por vez
     * (cada envio invalida o anterior), e ativar o 2FA e logar em seguida produz
     * dois e-mails em poucos minutos. Idênticos, era impossível saber qual estava
     * valendo — e usar o mais antigo dá "código inválido" sem explicar por quê.
     */
    public void sendOtpEmail(String toEmail, String toName, String code, boolean ativacao) {
        if (!enabled) {
            throw new EmailDeliveryException(
                    "Envio de e-mail desativado (MAIL_ENABLED). O 2FA por e-mail depende dele.");
        }
        if (toEmail == null || toEmail.isBlank()) {
            throw new EmailDeliveryException("Usuário sem e-mail cadastrado para receber o código.");
        }
        try {
            String firstName = toName != null && toName.contains(" ")
                    ? toName.substring(0, toName.indexOf(' ')) : (toName != null ? toName : "usuário");
            String formattedCode = code.substring(0, 3) + " " + code.substring(3);
            String html = """
                <!DOCTYPE html>
                <html lang="pt-BR">
                <body style="margin:0;padding:0;background:#0a1520;font-family:'Segoe UI',Arial,sans-serif;">
                  <table width="100%%" cellpadding="0" cellspacing="0" style="background:#0a1520;padding:32px 16px;">
                    <tr><td align="center">
                      <table width="480" cellpadding="0" cellspacing="0"
                             style="background:#0d1b2a;border:1px solid #1c2a3a;border-radius:8px;overflow:hidden;">
                        <tr><td style="background:#0a1520;padding:20px 28px;border-bottom:1px solid #1c2a3a;">
                          <span style="font-size:20px;font-weight:700;color:#00d4a0;letter-spacing:.05em;">◈ CyberAudit</span>
                        </td></tr>
                        <tr><td style="padding:32px 28px;text-align:center;">
                          <p style="margin:0 0 8px;color:#b8ccde;font-size:15px;">Olá, <strong style="color:#e0eaf4;">%s</strong>.</p>
                          <p style="margin:0 0 28px;color:#5a7a96;font-size:14px;">%s</p>
                          <div style="display:inline-block;padding:18px 36px;background:#0a1520;border:2px solid #00d4a0;
                                      border-radius:8px;margin-bottom:20px;">
                            <span style="font-family:monospace;font-size:36px;font-weight:700;
                                         letter-spacing:.25em;color:#00d4a0;">%s</span>
                          </div>
                          <p style="margin:0;color:#344d62;font-size:12px;">Válido por 10 minutos. Não compartilhe este código.</p>
                          <p style="margin:12px 0 0;color:#344d62;font-size:11px;">%s</p>
                        </td></tr>
                        <tr><td style="padding:16px 28px;border-top:1px solid #1c2a3a;color:#344d62;font-size:11px;text-align:center;">
                          Se você não tentou fazer login, ignore este email.
                        </td></tr>
                      </table>
                    </td></tr>
                  </table>
                </body></html>
                """.formatted(
                        escHtml(firstName),
                        ativacao ? "Código de teste da ativação do 2FA:"
                                 : "Seu código de verificação 2FA:",
                        formattedCode,
                        // Só um código vale por vez: avisar disso aqui evita a
                        // tentativa de usar um e-mail antigo que ainda está na caixa.
                        "Cada novo envio cancela o código anterior — use sempre o e-mail mais recente.");

            emailSender.send(from, toEmail,
                    ativacao ? "CyberAudit — Código de teste (ativação do 2FA)"
                             : "CyberAudit — Código de verificação 2FA",
                    html);
        } catch (RuntimeException e) {
            System.err.println("[EmailService] Falha ao enviar OTP: " + e.getMessage());
            // O transporte já reporta a causa concreta (código SMTP, resposta do
            // Resend). Reembrulhar só afastaria essa informação do log.
            if (e instanceof EmailDeliveryException ede) throw ede;
            throw new EmailDeliveryException(
                    "Não foi possível enviar o código por e-mail: " + e.getMessage(), e);
        }
    }

    /**
     * Notifica o admin/OWNER (e/ou a caixa da plataforma) sobre um novo feedback
     * de cliente contestando um achado. Silencioso se mail.enabled=false ou em falha.
     */
    /**
     * Link de redefinição de senha.
     *
     * Propaga a falha (como o OTP, diferente dos avisos): sem este e-mail não há
     * redefinição, e o serviço que chama precisa registrar o problema no log.
     * Quem decide não mostrar isso ao usuário é o PasswordResetService — contar
     * que o envio falhou revelaria que a conta existe.
     */
    public void sendPasswordResetEmail(String toEmail, String toName, String link, int minutos) {
        if (!enabled) {
            throw new EmailDeliveryException(
                    "Envio de e-mail desativado (MAIL_ENABLED). A redefinição de senha depende dele.");
        }
        String firstName = toName != null && toName.contains(" ")
                ? toName.substring(0, toName.indexOf(' ')) : (toName != null ? toName : "usuário");

        String html = """
            <!DOCTYPE html>
            <html lang="pt-BR">
            <body style="margin:0;padding:0;background:#0a1520;font-family:'Segoe UI',Arial,sans-serif;">
              <table width="100%%" cellpadding="0" cellspacing="0" style="background:#0a1520;padding:32px 16px;">
                <tr><td align="center">
                  <table width="480" cellpadding="0" cellspacing="0"
                         style="background:#0d1b2a;border:1px solid #1c2a3a;border-radius:8px;overflow:hidden;">
                    <tr><td style="background:#0a1520;padding:20px 28px;border-bottom:1px solid #1c2a3a;">
                      <span style="font-size:20px;font-weight:700;color:#00d4a0;letter-spacing:.05em;">◈ CyberAudit</span>
                    </td></tr>
                    <tr><td style="padding:32px 28px;text-align:center;">
                      <p style="margin:0 0 8px;color:#b8ccde;font-size:15px;">Olá, <strong style="color:#e0eaf4;">%s</strong>.</p>
                      <p style="margin:0 0 28px;color:#5a7a96;font-size:14px;">
                        Recebemos um pedido para redefinir a senha da sua conta.
                      </p>
                      <a href="%s" style="display:inline-block;padding:14px 32px;background:#00d4a0;color:#0a1520;
                                          font-size:15px;font-weight:700;text-decoration:none;border-radius:8px;">
                        Redefinir minha senha
                      </a>
                      <p style="margin:24px 0 0;color:#344d62;font-size:12px;">
                        O link vale por %d minutos e só pode ser usado uma vez.
                      </p>
                    </td></tr>
                    <tr><td style="padding:16px 28px;border-top:1px solid #1c2a3a;color:#344d62;font-size:11px;text-align:center;">
                      Se você não pediu isso, ignore este email — sua senha continua a mesma.
                    </td></tr>
                  </table>
                </td></tr>
              </table>
            </body></html>
            """.formatted(escHtml(firstName), escHtml(link), minutos);

        emailSender.send(from, toEmail, "CyberAudit — Redefinição de senha", html);
    }

    public void sendFeedbackNotification(String toEmail, String fromUserName, Feedback fb) {
        if (!enabled || toEmail == null || toEmail.isBlank()) return;
        try {
            String sender = fromUserName != null && !fromUserName.isBlank() ? fromUserName : "Um cliente";
            String target = fb.getFindingLabel() != null && !fb.getFindingLabel().isBlank()
                    ? fb.getFindingLabel()
                    : (fb.getModule() != null && !fb.getModule().isBlank() ? fb.getModule() : "scan inteiro");

            String html = """
                <!DOCTYPE html><html lang="pt-BR">
                <body style="margin:0;padding:0;background:#0a1520;font-family:'Segoe UI',Arial,sans-serif;">
                  <table width="100%%" cellpadding="0" cellspacing="0" style="background:#0a1520;padding:32px 16px;">
                    <tr><td align="center">
                      <table width="560" cellpadding="0" cellspacing="0"
                             style="background:#0d1b2a;border:1px solid #1c2a3a;border-radius:8px;overflow:hidden;">
                        <tr><td style="background:#0a1520;padding:20px 28px;border-bottom:3px solid #00d4a0;">
                          <span style="font-size:20px;font-weight:700;color:#00d4a0;letter-spacing:.05em;">◈ CyberAudit</span>
                          <span style="margin-left:16px;font-size:12px;color:#00d4a0;font-weight:700;letter-spacing:.08em;">✎ NOVO FEEDBACK</span>
                        </td></tr>
                        <tr><td style="padding:28px;">
                          <p style="margin:0 0 20px;color:#b8ccde;font-size:15px;">
                            <strong style="color:#e0eaf4;">%s</strong> contestou um resultado de scan.
                          </p>
                          <table width="100%%" cellpadding="0" cellspacing="0"
                                 style="background:#0a1520;border:1px solid #1c2a3a;border-radius:6px;margin-bottom:20px;">
                            <tr><td style="padding:18px 22px;">
                              <div style="font-size:11px;color:#5a7a96;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px;">Host</div>
                              <div style="font-size:16px;font-weight:600;color:#e0eaf4;font-family:monospace;margin-bottom:14px;">%s</div>
                              <div style="font-size:11px;color:#5a7a96;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px;">Alvo contestado</div>
                              <div style="font-size:14px;color:#e0eaf4;margin-bottom:14px;">%s</div>
                              <div style="font-size:11px;color:#5a7a96;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px;">Mensagem</div>
                              <div style="font-size:14px;color:#b8ccde;line-height:1.5;white-space:pre-wrap;">%s</div>
                            </td></tr>
                          </table>
                          <p style="margin:0;color:#5a7a96;font-size:13px;">Abra o painel de administração para triar este feedback.</p>
                        </td></tr>
                        <tr><td style="padding:16px 28px;border-top:1px solid #1c2a3a;color:#344d62;font-size:11px;text-align:center;">
                          Você recebeu este e-mail como administrador do CyberAudit.
                        </td></tr>
                      </table>
                    </td></tr>
                  </table>
                </body></html>
                """.formatted(escHtml(sender), escHtml(fb.getHost()), escHtml(target), escHtml(fb.getMessage()));

            emailSender.send(from, toEmail, "CyberAudit — Novo feedback: " + fb.getHost(), html);
        } catch (RuntimeException e) {
            System.err.println("[EmailService] Falha ao enviar notificação de feedback: " + e.getMessage());
        }
    }

    // ── HTML Template ─────────────────────────────────────────────────────────

    private String buildHtml(String name, String host, int score, String risk,
                             String color, ScanResult result) {
        var    scoreResult = result.getScore();
        int    issueCount = (scoreResult != null && scoreResult.getIssues() != null) ? scoreResult.getIssues().size() : 0;
        String firstName  = name != null && name.contains(" ")
                ? name.substring(0, name.indexOf(' ')) : (name != null ? name : "usuário");

        StringBuilder findings = new StringBuilder();
        if (scoreResult != null && scoreResult.getIssues() != null) {
            scoreResult.getIssues().stream().limit(5).forEach(issue -> {
                String sev      = issue.getSeverity() != null ? issue.getSeverity() : "INFO";
                String sevColor = switch (sev.toUpperCase()) {
                    case "CRITICAL" -> "#ff4040";
                    case "HIGH"     -> "#ff6b35";
                    case "MEDIUM"   -> "#f5a623";
                    default         -> "#7ec8a0";
                };
                findings.append("""
                    <tr>
                      <td style="padding:6px 0;border-bottom:1px solid #1c2a3a;">
                        <span style="display:inline-block;padding:2px 7px;border-radius:3px;
                              font-size:10px;font-weight:700;color:%s;
                              border:1px solid %s;font-family:monospace;">%s</span>
                      </td>
                      <td style="padding:6px 8px;border-bottom:1px solid #1c2a3a;
                            color:#b8ccde;font-size:13px;">%s</td>
                    </tr>
                    """.formatted(sevColor, sevColor, sev,
                        escHtml(issue.getTitle() != null ? issue.getTitle() : issue.getId())));
            });
            if (issueCount > 5) {
                findings.append("""
                    <tr><td colspan="2" style="padding:6px 0;color:#5a7a96;font-size:12px;">
                      + %d outros findings no relatório completo
                    </td></tr>
                    """.formatted(issueCount - 5));
            }
        }

        return """
            <!DOCTYPE html>
            <html lang="pt-BR">
            <head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
            <body style="margin:0;padding:0;background:#0a1520;font-family:'Segoe UI',Arial,sans-serif;">
              <table width="100%%" cellpadding="0" cellspacing="0" style="background:#0a1520;padding:32px 16px;">
                <tr><td align="center">
                  <table width="560" cellpadding="0" cellspacing="0"
                         style="background:#0d1b2a;border:1px solid #1c2a3a;border-radius:8px;overflow:hidden;">

                    <!-- Header -->
                    <tr>
                      <td style="background:#0a1520;padding:20px 28px;border-bottom:1px solid #1c2a3a;">
                        <span style="font-size:20px;font-weight:700;color:#00d4a0;letter-spacing:.05em;">
                          ◈ CyberAudit
                        </span>
                      </td>
                    </tr>

                    <!-- Body -->
                    <tr>
                      <td style="padding:28px;">

                        <p style="margin:0 0 16px;color:#b8ccde;font-size:15px;">
                          Olá, <strong style="color:#e0eaf4;">%s</strong>.
                        </p>
                        <p style="margin:0 0 24px;color:#5a7a96;font-size:14px;">
                          O scan do domínio abaixo foi concluído:
                        </p>

                        <!-- Score card -->
                        <table width="100%%" cellpadding="0" cellspacing="0"
                               style="background:#0a1520;border:1px solid #1c2a3a;border-radius:6px;
                                      margin-bottom:24px;">
                          <tr>
                            <td style="padding:20px 24px;">
                              <div style="font-size:12px;color:#5a7a96;text-transform:uppercase;
                                          letter-spacing:.08em;margin-bottom:4px;">Domínio</div>
                              <div style="font-size:17px;font-weight:600;color:#e0eaf4;
                                          font-family:monospace;margin-bottom:16px;">%s</div>
                              <table cellpadding="0" cellspacing="0">
                                <tr>
                                  <td style="padding-right:24px;">
                                    <div style="font-size:12px;color:#5a7a96;text-transform:uppercase;
                                                letter-spacing:.08em;margin-bottom:4px;">Score</div>
                                    <div style="font-size:32px;font-weight:700;color:%s;">%d<span style="font-size:14px;color:#5a7a96;">/100</span></div>
                                  </td>
                                  <td>
                                    <div style="font-size:12px;color:#5a7a96;text-transform:uppercase;
                                                letter-spacing:.08em;margin-bottom:4px;">Risco</div>
                                    <div style="display:inline-block;padding:4px 12px;border-radius:4px;
                                                font-size:13px;font-weight:700;color:%s;
                                                border:1px solid %s;">%s</div>
                                  </td>
                                </tr>
                              </table>
                            </td>
                          </tr>
                        </table>

                        <!-- Findings -->
                        %s

                        <!-- CTA -->
                        <p style="margin:24px 0 0;text-align:center;">
                          <a href="https://cyberaudit.app"
                             style="display:inline-block;padding:11px 28px;background:#00d4a0;
                                    color:#0a1520;font-weight:700;font-size:14px;border-radius:5px;
                                    text-decoration:none;">
                            Ver relatório completo →
                          </a>
                        </p>

                      </td>
                    </tr>

                    <!-- Footer -->
                    <tr>
                      <td style="padding:16px 28px;border-top:1px solid #1c2a3a;
                                 color:#344d62;font-size:11px;text-align:center;">
                        Você recebeu este email porque solicitou notificação de scan no CyberAudit.
                        Para desativar, desmarque "Notificar por email" antes de iniciar o próximo scan.
                      </td>
                    </tr>

                  </table>
                </td></tr>
              </table>
            </body>
            </html>
            """.formatted(
                // `host` aqui é a URL COMPLETA do scan (result.getUrl()): o SsrfGuard
                // valida esquema e host, mas path e query seguem livres, então é dado
                // de usuário indo direto para dentro do HTML.
                escHtml(firstName), escHtml(host),
                color, score,
                color, color, risk,
                issueCount > 0
                    ? "<p style='margin:0 0 8px;font-size:12px;color:#5a7a96;text-transform:uppercase;letter-spacing:.08em;'>Principais findings</p><table width='100%%' cellpadding='0' cellspacing='0'>" + findings + "</table>"
                    : "<p style='color:#00c87a;font-size:14px;'>✓ Nenhum problema encontrado.</p>"
        );
    }

    private String riskColor(String risk) {
        return switch (risk != null ? risk.toUpperCase() : "") {
            case "CRITICAL" -> "#ff4040";
            case "HIGH"     -> "#ff6b35";
            case "MEDIUM"   -> "#f5a623";
            case "LOW"      -> "#7ec8a0";
            case "SECURE"   -> "#00c87a";
            default         -> "#5a7a96";
        };
    }

    /**
     * Escapa dado de usuário para interpolação em HTML de e-mail.
     *
     * Aspas incluídas: sem elas, qualquer valor colocado dentro de um ATRIBUTO
     * (`href="%s"`, `title="%s"`) escaparia do atributo mesmo com &lt;/&gt; tratados.
     * Hoje nenhum valor de usuário cai em atributo, mas a próxima pessoa a editar
     * um template não deveria precisar saber disso.
     */
    private String escHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }
}
