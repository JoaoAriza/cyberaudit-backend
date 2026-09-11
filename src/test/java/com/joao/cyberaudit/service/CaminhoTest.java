package com.joao.cyberaudit.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * O caminho e o que separa duas paginas do mesmo dominio no historico.
 *
 * A coluna guarda a URL inteira, entao a mesma pagina chega escrita de varias
 * formas — com www, sem www, com barra no fim, com query. Se a normalizacao
 * divergir, o mesmo /login vira dois cards com scores diferentes.
 */
class CaminhoTest {

    @Test
    @DisplayName("a mesma pagina cai no mesmo caminho, venha como vier")
    void mesmaPaginaMesmoCaminho() {
        assertEquals("/login", ScanHistoryService.caminhoDe("https://site.com/login"));
        assertEquals("/login", ScanHistoryService.caminhoDe("https://www.site.com/login"));
        assertEquals("/login", ScanHistoryService.caminhoDe("http://site.com/login/"));
        assertEquals("/login", ScanHistoryService.caminhoDe("https://site.com/login?next=/painel"));
    }

    @Test
    @DisplayName("ausencia de caminho e a raiz")
    void raiz() {
        assertEquals("/", ScanHistoryService.caminhoDe("https://site.com"));
        assertEquals("/", ScanHistoryService.caminhoDe("https://site.com/"));
        assertEquals("/", ScanHistoryService.caminhoDe(null));
        assertEquals("/", ScanHistoryService.caminhoDe("   "));
    }

    @Test
    @DisplayName("URL torta cai na raiz em vez de derrubar a listagem")
    void urlInvalida() {
        assertEquals("/", ScanHistoryService.caminhoDe("h ttp://site com/login"));
    }

    @Test
    @DisplayName("caminho digitado a mao aceita com e sem barra inicial")
    void caminhoDigitado() {
        assertEquals("/login",  ScanHistoryService.normalizarCaminho("login"));
        assertEquals("/login",  ScanHistoryService.normalizarCaminho("/login/"));
        assertEquals("/a/b",    ScanHistoryService.normalizarCaminho("a/b"));
        assertEquals("/",       ScanHistoryService.normalizarCaminho(""));
    }
}
