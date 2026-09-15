package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.ImpactLevel;
import com.joao.cyberaudit.model.ImpactUndetermined;
import com.joao.cyberaudit.model.ScanResult;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * O laudo vai para o cliente: o rotulo de impacto tem de estar na caixa de resumo,
 * ao lado do score. A grade e a sobreposicao sao do PdfReportLayoutTest, que roda
 * o mesmo cenario ja com impacto.
 */
class PdfImpactoTest {

    @Test
    @DisplayName("a primeira pagina traz o nivel e a frase do impacto")
    void rotuloNoResumo() throws Exception {
        String pagina = primeiraPagina(Cenarios.completo().toBuilder().impact(ImpactLevel.PAYMENT).build());

        assertTrue(pagina.contains("IMPACT"), pagina);
        assertTrue(pagina.contains("PAYMENT"), pagina);
        assertTrue(pagina.contains("Payment data at risk"), pagina);
    }

    @Test
    @DisplayName("pagina que nao foi lida sai como NOT DETERMINED, com o status")
    void indeterminadoNoResumo() throws Exception {
        String pagina = primeiraPagina(Cenarios.completo().toBuilder()
                .impact(null).impactUndetermined(ImpactUndetermined.HTTP_STATUS).httpStatus(403).build());

        assertTrue(pagina.contains("NOT DETERMINED"), pagina);
        assertTrue(pagina.contains("HTTP 403"), pagina);
    }

    @Test
    @DisplayName("laudo sem impacto nao inventa um rotulo")
    void semImpactoNaoDesenha() throws Exception {
        String pagina = primeiraPagina(Cenarios.completo().toBuilder().impact(null).build());

        assertFalse(pagina.contains("Collects personal data"), pagina);
        assertFalse(pagina.contains("no data at risk"), pagina);
    }

    // ── Responsabilidade da plataforma nos cabecalhos ────────────────────────

    @Test
    @DisplayName("loja em plataforma anota que os cabecalhos sao responsabilidade dela")
    void notaDePlataformaNosHeaders() throws Exception {
        String texto = todasAsPaginas(Cenarios.completo().toBuilder().managedPlatform("VTEX").build());

        assertTrue(texto.contains("VTEX"), texto);
        assertTrue(texto.contains("responsibility"), texto);
    }

    @Test
    @DisplayName("sem plataforma detectada, nenhuma nota de responsabilidade")
    void semPlataformaSemNota() throws Exception {
        String texto = todasAsPaginas(Cenarios.completo().toBuilder().managedPlatform(null).build());

        assertFalse(texto.contains("responsibility"), texto);
    }

    private String primeiraPagina(ScanResult r) throws Exception {
        byte[] pdf = new PdfReportService().generatePdf(r, "");
        try (PDDocument doc = PDDocument.load(pdf)) {
            PDFTextStripper st = new PDFTextStripper();
            st.setStartPage(1);
            st.setEndPage(1);
            return st.getText(doc);
        }
    }

    private String todasAsPaginas(ScanResult r) throws Exception {
        byte[] pdf = new PdfReportService().generatePdf(r, "");
        try (PDDocument doc = PDDocument.load(pdf)) {
            return new PDFTextStripper().getText(doc);
        }
    }
}
