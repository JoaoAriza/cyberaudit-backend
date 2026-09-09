package com.joao.cyberaudit.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.joao.cyberaudit.model.*;
import com.joao.cyberaudit.repository.AuditLogRepository;
import com.joao.cyberaudit.repository.ScanRecordRepository;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.apache.pdfbox.text.TextPosition;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Os PDFs têm duas réguas verticais, e nada pode escapar delas.
 *
 * MOLDURA (45 .. 550): borda de caixa, tabela e rodapé.
 * CONTEÚDO (53 .. 542): todo texto que vive dentro de uma caixa.
 *
 * O que motivou o teste: cada seção foi escolhendo seu próprio recuo ao longo do
 * tempo — título de seção em M+10, caixa de resumo em M+12, linhas em M+8, célula
 * de tabela em M+4, e três alinhamentos à direita diferentes (PW-M, -8 e -12).
 * Nada estourava a página, então nenhum teste pegava — só o olho de quem lia o
 * relatório, que via cinco colunas onde deviam existir duas.
 */
class PdfReportLayoutTest {

    private static final float M = 45f, PAD = 8f, PW = 595.28f;
    private static final float LX = M + PAD;
    private static final float RX = PW - M - PAD;
    private static final float TOLERANCIA = 0.6f;

    @Test
    @DisplayName("o laudo de scan mantém tudo na coluna de conteúdo")
    void scanDentroDaGrade() throws Exception {
        assertNaGrade(new PdfReportService().generatePdf(cenarioScan(), ""));
    }

    @Test
    @DisplayName("o relatório executivo segue a mesma grade")
    void executivoDentroDaGrade() throws Exception {
        ScanRecordRepository scans = mock(ScanRecordRepository.class, RETURNS_DEEP_STUBS);
        AuditLogRepository   logs  = mock(AuditLogRepository.class, RETURNS_DEEP_STUBS);
        when(scans.findLatestPerHostByAccount(any(), any())).thenReturn(List.of());
        when(scans.findByHostOrderByScannedAtDesc(any(), any())).thenReturn(List.of());

        ExecutivePdfReportService exec =
                new ExecutivePdfReportService(scans, logs, new ObjectMapper());

        Account conta = Account.builder()
                .id(UUID.randomUUID())
                .type(AccountType.COMPANY)
                .plan(Plan.ENTERPRISE)
                .displayName("Conta de Teste com Nome Longo")
                .companyName("Empresa Exemplo Ltda")
                .build();
        Domain dominio = Domain.builder()
                .id(UUID.randomUUID())
                .host("um-host-bastante-comprido.exemplo.com.br")
                .verified(true)
                .build();

        assertNaGrade(exec.generate(conta, List.of(dominio),
                ExecutivePdfReportService.ReportScope.DOMAINS, null, null));
    }

    // ── Verificação ──────────────────────────────────────────────────────────

    private void assertNaGrade(byte[] pdf) throws Exception {
        List<String> fora = new ArrayList<>();
        try (PDDocument doc = PDDocument.load(pdf)) {
            PDFTextStripper stripper = new PDFTextStripper() {
                @Override
                protected void writeString(String texto, List<TextPosition> pos) {
                    if (pos.isEmpty() || texto.isBlank()) return;
                    TextPosition ini = pos.get(0), fim = pos.get(pos.size() - 1);
                    float x0 = ini.getXDirAdj();
                    float x1 = fim.getXDirAdj() + fim.getWidthDirAdj();

                    // Rodapé é o único texto que vive na moldura, e não numa caixa.
                    boolean rodape = texto.contains("Confidential") || texto.startsWith("Page ");
                    float limEsq = rodape ? M      : LX;
                    float limDir = rodape ? PW - M : RX;

                    if (x0 < limEsq - TOLERANCIA || x1 > limDir + TOLERANCIA) {
                        fora.add(String.format("x0=%.1f x1=%.1f (esperado %.1f..%.1f) \"%s\"",
                                x0, x1, limEsq, limDir, texto));
                    }
                }
            };
            stripper.setSortByPosition(true);
            stripper.getText(doc);
        }
        assertTrue(fora.isEmpty(), "texto fora da grade:\n" + String.join("\n", fora));
    }

    // ── Cenário ──────────────────────────────────────────────────────────────

    /** Cobre os renderizadores de linha que a tela mostra: issues, portas, kv, mudanças. */
    private ScanResult cenarioScan() {
        SecurityIssue issue = new SecurityIssue();
        issue.setId("SSL_INVALID");
        issue.setTitle("Certificado SSL invalido com um titulo longo o bastante para quebrar em "
                + "mais de uma linha dentro da coluna de conteudo");
        issue.setSeverity("HIGH");
        issue.setImpact("Usuarios recebem alerta de seguranca; comunicacao pode ser insegura e o "
                + "trafego fica exposto a interceptacao ativa no caminho.");
        issue.setRecommendation("Renovar e configurar corretamente o certificado e a cadeia "
                + "intermediaria, conferindo a ordem dos certificados servidos.");

        ScoreResult score = new ScoreResult();
        score.setScore(8);
        score.setRiskLevel(RiskLevel.CRITICAL);
        score.setIssues(List.of(issue));
        score.setNotes(List.of("HTTPS e certificado valido: OK", "WAF detectado (Cloudflare): +4"));

        PortFinding ftp = new PortFinding();
        ftp.setPort(21); ftp.setService("FTP"); ftp.setState("OPEN"); ftp.setSeverity("HIGH");
        ftp.setLatencyMs(182L);
        ftp.setImpact("FTP exposto: transmite credenciais em texto plano; permite enumeracao e "
                + "exfiltracao de arquivos do servidor.");
        ftp.setRecommendation("Desative FTP. Use SFTP (porta 22) ou FTPS. Restrinja por firewall/VPN.");

        ScanChange mudanca = new ScanChange();
        mudanca.setCategory("SSL"); mudanca.setField("certificate validity");
        mudanca.setChangeType("DEGRADED"); mudanca.setSeverity("HIGH");
        mudanca.setOldValue("valido"); mudanca.setNewValue("invalido");
        mudanca.setDescription("Certificado SSL tornou-se invalido");

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("strict-transport-security", "max-age=31536000; includeSubDomains");
        headers.put("content-security-policy", "default-src 'self'; script-src 'self' 'unsafe-inline'");

        Map<String, String> modulos = new LinkedHashMap<>();
        modulos.put("HTTP_FETCH", "ERROR");

        return ScanResult.builder()
                .url("http://sgsistemas.com.br")
                .finalUrl("http://sgsistemas.com.br/")
                .httpStatus(200)
                .activeMode(true)
                .score(score)
                .headers(headers)
                .moduleStatus(modulos)
                .openPorts(List.of(ftp))
                .changes(List.of(mudanca))
                .build();
    }
}
