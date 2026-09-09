package com.joao.cyberaudit.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.joao.cyberaudit.model.*;
import com.joao.cyberaudit.repository.AuditLogRepository;
import com.joao.cyberaudit.repository.ScanRecordRepository;
import org.apache.pdfbox.contentstream.PDFGraphicsStreamEngine;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.text.PDFTextStripper;
import org.apache.pdfbox.text.TextPosition;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.awt.geom.Point2D;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Verificacao de layout do laudo, medida no PDF gerado — nao no codigo.
 *
 * Tres invariantes, cada uma nascida de um defeito real que so aparecia lendo o
 * documento:
 *
 *  1. GRADE — duas reguas verticais: moldura (45..550) para borda de caixa,
 *     tabela e rodape; conteudo (53..542) para texto dentro de caixa. Antes eram
 *     cinco a esquerda e tres a direita.
 *  2. TEXTO SOBRE TEXTO — a nota de abertura dos CVEs subia por cima do titulo do
 *     primeiro CVE, e o rotulo SCORE encostava nos digitos de 20pt.
 *  3. LINHA CORTANDO TEXTO — a divisoria entre issues passava por dentro do
 *     titulo da issue seguinte, e o separador do breakdown riscava o Final score.
 *
 * Nenhum desses defeitos estourava a margem, entao nenhuma verificacao de borda
 * pegava — so o olho de quem abria o arquivo.
 */
class PdfReportLayoutTest {

    private static final float M = 45f, PAD = 8f, PW = 595.28f;
    private static final float LX = M + PAD;
    private static final float RX = PW - M - PAD;
    private static final float TOLERANCIA = 0.6f;

    private record Caixa(int pag, float x0, float x1, float base, float topo, float fundo, String txt) {}
    private record Linha(int pag, float x0, float x1, float y) {}

    @Test
    @DisplayName("o laudo de scan mantem tudo na coluna de conteudo")
    void scanDentroDaGrade() throws Exception {
        assertNaGrade(laudo());
    }

    @Test
    @DisplayName("o relatorio executivo segue a mesma grade")
    void executivoDentroDaGrade() throws Exception {
        assertNaGrade(executivo());
    }

    @Test
    @DisplayName("nenhum texto e desenhado por cima de outro")
    void semTextoSobreposto() throws Exception {
        List<Caixa> textos = textos(laudo());
        List<String> colisoes = new ArrayList<>();
        for (int i = 0; i < textos.size(); i++) {
            for (int j = i + 1; j < textos.size(); j++) {
                Caixa a = textos.get(i), b = textos.get(j);
                if (a.pag() != b.pag()) continue;
                boolean cruzaX = a.x0() < b.x1() - 0.5f && b.x0() < a.x1() - 0.5f;
                boolean cruzaY = a.fundo() < b.topo() - 0.5f && b.fundo() < a.topo() - 0.5f;
                if (cruzaX && cruzaY)
                    colisoes.add(String.format("p%d [%s] (%.1f) sobre [%s] (%.1f)",
                            a.pag(), corta(a.txt()), a.base(), corta(b.txt()), b.base()));
            }
        }
        assertTrue(colisoes.isEmpty(), "texto sobre texto:\n" + String.join("\n", colisoes));
    }

    @Test
    @DisplayName("nenhuma divisoria passa por dentro de um texto")
    void semLinhaCortandoTexto() throws Exception {
        byte[] pdf = laudo();
        List<Caixa> textos = textos(pdf);
        List<Linha> linhas = linhas(pdf);
        List<String> cortes = new ArrayList<>();
        for (Caixa c : textos) {
            for (Linha l : linhas) {
                if (l.pag() != c.pag()) continue;
                if (l.x0() < c.x1() - 0.5f && c.x0() < l.x1() - 0.5f
                        && l.y() > c.fundo() + 0.3f && l.y() < c.topo() - 0.3f)
                    cortes.add(String.format("p%d linha y=%.1f corta [%s]",
                            c.pag(), l.y(), corta(c.txt())));
            }
        }
        assertTrue(cortes.isEmpty(), "linha cortando texto:\n" + String.join("\n", cortes));
    }

    private byte[] laudo() throws Exception {
        return new PdfReportService().generatePdf(Cenarios.completo(), "");
    }

    private byte[] executivo() {
        ScanRecordRepository scans = mock(ScanRecordRepository.class, RETURNS_DEEP_STUBS);
        AuditLogRepository   logs  = mock(AuditLogRepository.class, RETURNS_DEEP_STUBS);
        when(scans.findLatestPerHostByAccount(any(), any())).thenReturn(List.of());
        when(scans.findByHostOrderByScannedAtDesc(any(), any())).thenReturn(List.of());

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

        return new ExecutivePdfReportService(scans, logs, new ObjectMapper())
                .generate(conta, List.of(dominio),
                        ExecutivePdfReportService.ReportScope.DOMAINS, null, null);
    }

    private void assertNaGrade(byte[] pdf) throws Exception {
        List<String> fora = new ArrayList<>();
        for (Caixa c : textos(pdf)) {
            // Texto que rotula um elemento de largura cheia acompanha a MOLDURA,
            // porque a borda de referencia dele e a do proprio elemento.
            boolean naMoldura = c.txt().contains("Confidential")
                    || c.txt().startsWith("Page ")
                    || c.txt().startsWith("SEVERITY DISTRIBUTION");
            float limEsq = naMoldura ? M      : LX;
            float limDir = naMoldura ? PW - M : RX;
            if (c.x0() < limEsq - TOLERANCIA || c.x1() > limDir + TOLERANCIA)
                fora.add(String.format("x0=%.1f x1=%.1f (esperado %.1f..%.1f) [%s]",
                        c.x0(), c.x1(), limEsq, limDir, corta(c.txt())));
        }
        assertTrue(fora.isEmpty(), "texto fora da grade:\n" + String.join("\n", fora));
    }

    private List<Caixa> textos(byte[] pdf) throws Exception {
        List<Caixa> out = new ArrayList<>();
        try (PDDocument doc = PDDocument.load(pdf)) {
            final float ph = doc.getPage(0).getMediaBox().getHeight();
            PDFTextStripper st = new PDFTextStripper() {
                @Override protected void writeString(String t, List<TextPosition> pos) {
                    if (pos.isEmpty() || t.isBlank()) return;
                    TextPosition a = pos.get(0), z = pos.get(pos.size() - 1);
                    float size = a.getFontSizeInPt();
                    float base = ph - a.getYDirAdj();
                    out.add(new Caixa(getCurrentPageNo(), a.getXDirAdj(),
                            z.getXDirAdj() + z.getWidthDirAdj(), base,
                            base + size * 0.72f, base - size * 0.22f, t.trim()));
                }
            };
            st.setSortByPosition(true);
            st.getText(doc);
        }
        return out;
    }

    /** Divisorias: retangulos preenchidos de ate 1,2pt de altura. */
    private List<Linha> linhas(byte[] pdf) throws Exception {
        List<Linha> out = new ArrayList<>();
        try (PDDocument doc = PDDocument.load(pdf)) {
            for (int p = 0; p < doc.getNumberOfPages(); p++) {
                PDPage page = doc.getPage(p);
                final int pn = p + 1;
                new PDFGraphicsStreamEngine(page) {
                    private final List<Point2D> pts = new ArrayList<>();
                    @Override public void appendRectangle(Point2D a, Point2D b, Point2D c, Point2D d) {
                        pts.clear(); pts.add(a); pts.add(b); pts.add(c); pts.add(d);
                    }
                    @Override public void fillPath(int w) {
                        if (pts.size() != 4) return;
                        double x0=Double.MAX_VALUE,x1=-Double.MAX_VALUE,y0=Double.MAX_VALUE,y1=-Double.MAX_VALUE;
                        for (Point2D q : pts) { x0=Math.min(x0,q.getX()); x1=Math.max(x1,q.getX());
                                                y0=Math.min(y0,q.getY()); y1=Math.max(y1,q.getY()); }
                        if (y1 - y0 <= 1.2) out.add(new Linha(pn,(float)x0,(float)x1,(float)y0));
                        pts.clear();
                    }
                    @Override public void drawImage(org.apache.pdfbox.pdmodel.graphics.image.PDImage i) {}
                    @Override public void clip(int w) {}
                    @Override public void moveTo(float x, float y) {}
                    @Override public void lineTo(float x, float y) {}
                    @Override public Point2D getCurrentPoint() { return new Point2D.Float(); }
                    @Override public void closePath() {}
                    @Override public void endPath() { pts.clear(); }
                    @Override public void strokePath() { pts.clear(); }
                    @Override public void fillAndStrokePath(int w) { fillPath(w); }
                    @Override public void shadingFill(org.apache.pdfbox.cos.COSName n) {}
                    @Override public void curveTo(float a,float b,float c,float d,float e,float g) {}
                }.processPage(page);
            }
        }
        return out;
    }

    private static String corta(String s) { return s.length() > 40 ? s.substring(0, 40) + "..." : s; }
}
