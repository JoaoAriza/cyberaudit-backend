package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.ImpactLevel;
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
    @DisplayName("laudo sem impacto nao inventa um rotulo")
    void semImpactoNaoDesenha() throws Exception {
        String pagina = primeiraPagina(Cenarios.completo().toBuilder().impact(null).build());

        assertFalse(pagina.contains("Collects personal data"), pagina);
        assertFalse(pagina.contains("no data at risk"), pagina);
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
}
