package com.joao.cyberaudit.service;

import com.joao.cyberaudit.exception.EmailDeliveryException;
import com.joao.cyberaudit.model.Feedback;
import com.joao.cyberaudit.model.ScanResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    private final EmailSender    emailSender;
    private final MessageCatalog catalog;

    @Value("${mail.enabled:false}")
    private boolean enabled;

    @Value("${mail.from:noreply@cyberaudit.app}")
    private String from;

    public EmailService(EmailSender emailSender, MessageCatalog catalog) {
        this.emailSender = emailSender;
        this.catalog     = catalog;
    }

    /**
     * A saudação inteira, com o primeiro nome já escapado e estilizado.
     *
     * O nome entra como PARÂMETRO de uma frase completa, em vez de a frase ser
     * partida em "Olá, " + nome + ".": a ordem das palavras muda de idioma para
     * idioma, e frase picada não sobrevive à tradução.
     */
    private String saudacao(String nome) {
        String primeiro = nome != null && nome.contains(" ")
                ? nome.substring(0, nome.indexOf(' '))
                : (nome != null && !nome.isBlank() ? nome : catalog.email("defaultName"));
        return catalog.email("greeting",
                "<strong style=\"color:#e0eaf4;\">" + escHtml(primeiro) + "</strong>");
    }

    /** Idioma da mensagem, para o atributo lang do HTML. */
    private String tagDeIdioma() {
        return org.springframework.context.i18n.LocaleContextHolder.getLocale().toLanguageTag();
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

            String subject = catalog.email("scan.subject", host, score);
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
                    ? "<p style='margin:0 0 6px;font-size:11px;color:#5a7a96;text-transform:uppercase;"
                      + "letter-spacing:.08em;'>" + catalog.email("degradation.criticalFindings") + "</p>"
                      + "<table width='100%' cellpadding='0' cellspacing='0'>" + findings + "</table>"
                    : "";

            String html = """
                <!DOCTYPE html><html lang="%s">
                <body style="margin:0;padding:0;background:#0a1520;font-family:'Segoe UI',Arial,sans-serif;">
                  <table width="100%%" cellpadding="0" cellspacing="0" style="background:#0a1520;padding:32px 16px;">
                    <tr><td align="center">
                      <table width="560" cellpadding="0" cellspacing="0"
                             style="background:#0d1b2a;border:1px solid #1c2a3a;border-radius:8px;overflow:hidden;">
                        <tr><td style="background:#0a1520;padding:20px 28px;border-bottom:3px solid #ff4040;">
                          <span style="font-size:20px;font-weight:700;color:#00d4a0;letter-spacing:.05em;">◈ CyberAudit</span>
                          <span style="margin-left:16px;font-size:12px;color:#ff4040;font-weight:700;letter-spacing:.08em;">%s</span>
                        </td></tr>
                        <tr><td style="padding:28px;">
                          <p style="margin:0 0 16px;color:#b8ccde;font-size:15px;">
                            %s
                          </p>
                          <p style="margin:0 0 20px;color:#5a7a96;font-size:14px;">
                            %s
                          </p>
                          <table width="100%%" cellpadding="0" cellspacing="0"
                                 style="background:#0a1520;border:1px solid #ff4040;border-radius:6px;margin-bottom:20px;">
                            <tr><td style="padding:20px 24px;">
                              <div style="font-size:12px;color:#5a7a96;text-transform:uppercase;
                                          letter-spacing:.08em;margin-bottom:4px;">%s</div>
                              <div style="font-size:17px;font-weight:600;color:#e0eaf4;
                                          font-family:monospace;margin-bottom:16px;">%s</div>
                              <table cellpadding="0" cellspacing="0">
                                <tr>
                                  <td style="padding-right:28px;">
                                    <div style="font-size:11px;color:#5a7a96;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px;">%s</div>
                                    <div style="font-size:24px;font-weight:700;color:#5a7a96;">%d<span style="font-size:12px;">/100</span></div>
                                  </td>
                                  <td style="padding-right:28px;">
                                    <div style="font-size:18px;color:#ff4040;font-weight:700;">▼ %d</div>
                                  </td>
                                  <td style="padding-right:28px;">
                                    <div style="font-size:11px;color:#5a7a96;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px;">%s</div>
                                    <div style="font-size:24px;font-weight:700;color:%s;">%d<span style="font-size:12px;">/100</span></div>
                                  </td>
                                  <td>
                                    <div style="font-size:11px;color:#5a7a96;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px;">%s</div>
                                    <div style="display:inline-block;padding:4px 10px;border-radius:4px;
                                                font-size:12px;font-weight:700;color:%s;border:1px solid %s;">%s</div>
                                  </td>
                                </tr>
                              </table>
                            </td></tr>
                          </table>
                          <p style="margin:0 0 16px;color:#b8ccde;font-size:13px;"><strong>%s</strong> %s</p>
                          %s
                          <p style="margin:24px 0 0;text-align:center;">
                            <a href="https://cyberaudit.app"
                               style="display:inline-block;padding:11px 28px;background:#ff4040;
                                      color:#fff;font-weight:700;font-size:14px;border-radius:5px;
                                      text-decoration:none;">
                              %s
                            </a>
                          </p>
                        </td></tr>
                        <tr><td style="padding:16px 28px;border-top:1px solid #1c2a3a;
                                       color:#344d62;font-size:11px;text-align:center;">
                          %s
                        </td></tr>
                      </table>
                    </td></tr>
                  </table>
                </body></html>
                """.formatted(
                        tagDeIdioma(),
                        catalog.email("degradation.badge"),
                        saudacao(toName),
                        catalog.email("degradation.intro"),
                        catalog.email("degradation.domain"),   escHtml(host),
                        catalog.email("degradation.previousScore"), oldScore,
                        drop,
                        catalog.email("degradation.currentScore"),  color, newScore,
                        catalog.email("degradation.risk"),     color, color, newRisk,
                        catalog.email("degradation.reason"),   escHtml(reason),
                        findingsSection,
                        catalog.email("degradation.cta"),
                        catalog.email("degradation.footer"));

            emailSender.send(from, toEmail,
                    catalog.email("degradation.subject", host, oldScore, newScore), html);
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
            String formattedCode = code.substring(0, 3) + " " + code.substring(3);
            String html = """
                <!DOCTYPE html>
                <html lang="%s">
                <body style="margin:0;padding:0;background:#0a1520;font-family:'Segoe UI',Arial,sans-serif;">
                  <table width="100%%" cellpadding="0" cellspacing="0" style="background:#0a1520;padding:32px 16px;">
                    <tr><td align="center">
                      <table width="480" cellpadding="0" cellspacing="0"
                             style="background:#0d1b2a;border:1px solid #1c2a3a;border-radius:8px;overflow:hidden;">
                        <tr><td style="background:#0a1520;padding:20px 28px;border-bottom:1px solid #1c2a3a;">
                          <span style="font-size:20px;font-weight:700;color:#00d4a0;letter-spacing:.05em;">◈ CyberAudit</span>
                        </td></tr>
                        <tr><td style="padding:32px 28px;text-align:center;">
                          <p style="margin:0 0 8px;color:#b8ccde;font-size:15px;">%s</p>
                          <p style="margin:0 0 28px;color:#5a7a96;font-size:14px;">%s</p>
                          <div style="display:inline-block;padding:18px 36px;background:#0a1520;border:2px solid #00d4a0;
                                      border-radius:8px;margin-bottom:20px;">
                            <span style="font-family:monospace;font-size:36px;font-weight:700;
                                         letter-spacing:.25em;color:#00d4a0;">%s</span>
                          </div>
                          <p style="margin:0;color:#344d62;font-size:12px;">%s</p>
                          <p style="margin:12px 0 0;color:#344d62;font-size:11px;">%s</p>
                        </td></tr>
                        <tr><td style="padding:16px 28px;border-top:1px solid #1c2a3a;color:#344d62;font-size:11px;text-align:center;">
                          %s
                        </td></tr>
                      </table>
                    </td></tr>
                  </table>
                </body></html>
                """.formatted(
                        tagDeIdioma(),
                        saudacao(toName),
                        catalog.email(ativacao ? "otp.introTest" : "otp.intro"),
                        formattedCode,
                        catalog.email("otp.validity"),
                        // Só um código vale por vez: avisar disso aqui evita a
                        // tentativa de usar um e-mail antigo que ainda está na caixa.
                        catalog.email("otp.latestOnly"),
                        catalog.email("otp.footer"));

            emailSender.send(from, toEmail,
                    catalog.email(ativacao ? "otp.subjectTest" : "otp.subject"),
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

        String html = """
            <!DOCTYPE html>
            <html lang="%s">
            <body style="margin:0;padding:0;background:#0a1520;font-family:'Segoe UI',Arial,sans-serif;">
              <table width="100%%" cellpadding="0" cellspacing="0" style="background:#0a1520;padding:32px 16px;">
                <tr><td align="center">
                  <table width="480" cellpadding="0" cellspacing="0"
                         style="background:#0d1b2a;border:1px solid #1c2a3a;border-radius:8px;overflow:hidden;">
                    <tr><td style="background:#0a1520;padding:20px 28px;border-bottom:1px solid #1c2a3a;">
                      <span style="font-size:20px;font-weight:700;color:#00d4a0;letter-spacing:.05em;">◈ CyberAudit</span>
                    </td></tr>
                    <tr><td style="padding:32px 28px;text-align:center;">
                      <p style="margin:0 0 8px;color:#b8ccde;font-size:15px;">%s</p>
                      <p style="margin:0 0 28px;color:#5a7a96;font-size:14px;">
                        %s
                      </p>
                      <a href="%s" style="display:inline-block;padding:14px 32px;background:#00d4a0;color:#0a1520;
                                          font-size:15px;font-weight:700;text-decoration:none;border-radius:8px;">
                        %s
                      </a>
                      <p style="margin:24px 0 0;color:#344d62;font-size:12px;">
                        %s
                      </p>
                    </td></tr>
                    <tr><td style="padding:16px 28px;border-top:1px solid #1c2a3a;color:#344d62;font-size:11px;text-align:center;">
                      %s
                    </td></tr>
                  </table>
                </td></tr>
              </table>
            </body></html>
            """.formatted(
                    tagDeIdioma(),
                    saudacao(toName),
                    catalog.email("reset.intro"),
                    escHtml(link),
                    catalog.email("reset.cta"),
                    catalog.email("reset.validity", minutos),
                    catalog.email("reset.footer"));

        emailSender.send(from, toEmail, catalog.email("reset.subject"), html);
    }

    public void sendFeedbackNotification(String toEmail, String fromUserName, Feedback fb) {
        if (!enabled || toEmail == null || toEmail.isBlank()) return;
        try {
            String sender = fromUserName != null && !fromUserName.isBlank() ? fromUserName : "Um cliente";
            String target = fb.getFindingLabel() != null && !fb.getFindingLabel().isBlank()
                    ? fb.getFindingLabel()
                    : (fb.getModule() != null && !fb.getModule().isBlank() ? fb.getModule() : catalog.email("feedback.wholeScan"));

            String html = """
                <!DOCTYPE html><html lang="%s">
                <body style="margin:0;padding:0;background:#0a1520;font-family:'Segoe UI',Arial,sans-serif;">
                  <table width="100%%" cellpadding="0" cellspacing="0" style="background:#0a1520;padding:32px 16px;">
                    <tr><td align="center">
                      <table width="560" cellpadding="0" cellspacing="0"
                             style="background:#0d1b2a;border:1px solid #1c2a3a;border-radius:8px;overflow:hidden;">
                        <tr><td style="background:#0a1520;padding:20px 28px;border-bottom:3px solid #00d4a0;">
                          <span style="font-size:20px;font-weight:700;color:#00d4a0;letter-spacing:.05em;">◈ CyberAudit</span>
                          <span style="margin-left:16px;font-size:12px;color:#00d4a0;font-weight:700;letter-spacing:.08em;">%s</span>
                        </td></tr>
                        <tr><td style="padding:28px;">
                          <p style="margin:0 0 20px;color:#b8ccde;font-size:15px;">
                            %s
                          </p>
                          <table width="100%%" cellpadding="0" cellspacing="0"
                                 style="background:#0a1520;border:1px solid #1c2a3a;border-radius:6px;margin-bottom:20px;">
                            <tr><td style="padding:18px 22px;">
                              <div style="font-size:11px;color:#5a7a96;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px;">%s</div>
                              <div style="font-size:16px;font-weight:600;color:#e0eaf4;font-family:monospace;margin-bottom:14px;">%s</div>
                              <div style="font-size:11px;color:#5a7a96;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px;">%s</div>
                              <div style="font-size:14px;color:#e0eaf4;margin-bottom:14px;">%s</div>
                              <div style="font-size:11px;color:#5a7a96;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px;">%s</div>
                              <div style="font-size:14px;color:#b8ccde;line-height:1.5;white-space:pre-wrap;">%s</div>
                            </td></tr>
                          </table>
                          <p style="margin:0;color:#5a7a96;font-size:13px;">%s</p>
                        </td></tr>
                        <tr><td style="padding:16px 28px;border-top:1px solid #1c2a3a;color:#344d62;font-size:11px;text-align:center;">
                          %s
                        </td></tr>
                      </table>
                    </td></tr>
                  </table>
                </body></html>
                """.formatted(
                        tagDeIdioma(),
                        catalog.email("feedback.badge"),
                        catalog.email("feedback.intro",
                                "<strong style=\"color:#e0eaf4;\">" + escHtml(sender) + "</strong>"),
                        catalog.email("feedback.host"),    escHtml(fb.getHost()),
                        catalog.email("feedback.target"),  escHtml(target),
                        catalog.email("feedback.message"), escHtml(fb.getMessage()),
                        catalog.email("feedback.action"),
                        catalog.email("feedback.footer"));

            emailSender.send(from, toEmail, catalog.email("feedback.subject", fb.getHost()), html);
        } catch (RuntimeException e) {
            System.err.println("[EmailService] Falha ao enviar notificação de feedback: " + e.getMessage());
        }
    }

    // ── HTML Template ─────────────────────────────────────────────────────────

    private String buildHtml(String name, String host, int score, String risk,
                             String color, ScanResult result) {
        var    scoreResult = result.getScore();
        int    issueCount = (scoreResult != null && scoreResult.getIssues() != null) ? scoreResult.getIssues().size() : 0;

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
                      %s
                    </td></tr>
                    """.formatted(catalog.email("scan.more", issueCount - 5)));
            }
        }

        return """
            <!DOCTYPE html>
            <html lang="%s">
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
                          %s
                        </p>
                        <p style="margin:0 0 24px;color:#5a7a96;font-size:14px;">
                          %s
                        </p>

                        <!-- Score card -->
                        <table width="100%%" cellpadding="0" cellspacing="0"
                               style="background:#0a1520;border:1px solid #1c2a3a;border-radius:6px;
                                      margin-bottom:24px;">
                          <tr>
                            <td style="padding:20px 24px;">
                              <div style="font-size:12px;color:#5a7a96;text-transform:uppercase;
                                          letter-spacing:.08em;margin-bottom:4px;">%s</div>
                              <div style="font-size:17px;font-weight:600;color:#e0eaf4;
                                          font-family:monospace;margin-bottom:16px;">%s</div>
                              <table cellpadding="0" cellspacing="0">
                                <tr>
                                  <td style="padding-right:24px;">
                                    <div style="font-size:12px;color:#5a7a96;text-transform:uppercase;
                                                letter-spacing:.08em;margin-bottom:4px;">%s</div>
                                    <div style="font-size:32px;font-weight:700;color:%s;">%d<span style="font-size:14px;color:#5a7a96;">/100</span></div>
                                  </td>
                                  <td>
                                    <div style="font-size:12px;color:#5a7a96;text-transform:uppercase;
                                                letter-spacing:.08em;margin-bottom:4px;">%s</div>
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
                            %s
                          </a>
                        </p>

                      </td>
                    </tr>

                    <!-- Footer -->
                    <tr>
                      <td style="padding:16px 28px;border-top:1px solid #1c2a3a;
                                 color:#344d62;font-size:11px;text-align:center;">
                        %s
                        %s
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
                tagDeIdioma(),
                saudacao(name),
                catalog.email("scan.intro"),
                catalog.email("scan.domain"), escHtml(host),
                catalog.email("scan.score"),  color, score,
                catalog.email("scan.risk"),   color, color, risk,
                issueCount > 0
                    // `100%` sem duplicar: esta String é ARGUMENTO do formatted, não o
                    // template — o `%%` que estava aqui saía literal no HTML.
                    ? "<p style='margin:0 0 8px;font-size:12px;color:#5a7a96;text-transform:uppercase;"
                      + "letter-spacing:.08em;'>" + catalog.email("scan.topFindings") + "</p>"
                      + "<table width='100%' cellpadding='0' cellspacing='0'>" + findings + "</table>"
                    : "<p style='color:#00c87a;font-size:14px;'>" + catalog.email("scan.noIssues") + "</p>",
                catalog.email("scan.cta"),
                catalog.email("scan.footer1"),
                catalog.email("scan.footer2")
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
