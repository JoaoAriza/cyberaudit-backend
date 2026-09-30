package com.joao.cyberaudit.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CpfUtilTest {

    @Test
    @DisplayName("CPF válido, sem máscara")
    void cpfValidoSemMascara() {
        assertTrue(CpfUtil.isValid("11144477735"));
    }

    @Test
    @DisplayName("CPF válido, com máscara")
    void cpfValidoComMascara() {
        assertTrue(CpfUtil.isValid("111.444.777-35"));
    }

    @Test
    @DisplayName("Dígito verificador não confere — mesmo com 11 dígitos")
    void digitoVerificadorInvalido() {
        assertFalse(CpfUtil.isValid("11144477736"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "00000000000", "11111111111", "22222222222", "99999999999",
    })
    @DisplayName("Sequência trivial rejeitada mesmo passando no módulo 11")
    void sequenciaTrivialRecusada(String cpf) {
        assertFalse(CpfUtil.isValid(cpf));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"123", "111444777350"})
    @DisplayName("Nulo, vazio ou tamanho errado — inválido")
    void tamanhoErrado(String cpf) {
        assertFalse(CpfUtil.isValid(cpf));
    }

    @Test
    @DisplayName("strip remove pontuação, format devolve a máscara")
    void stripEFormat() {
        assertEquals("11144477735", CpfUtil.strip("111.444.777-35"));
        assertEquals("111.444.777-35", CpfUtil.format("11144477735"));
    }
}
