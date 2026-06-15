package com.joao.cyberaudit.util;

/**
 * Utilitário para validação e formatação de CNPJ.
 *
 * Algoritmo: módulo 11 com dois dígitos verificadores (Receita Federal).
 * Referência: https://www.receita.fazenda.gov.br/aplicacoes/atcta/cpf/orientacoes.htm
 */
public final class CnpjUtil {

    private CnpjUtil() {}

    /**
     * Valida um CNPJ (aceita com ou sem máscara).
     *
     * @param raw string bruta — pode conter pontos, barra e hífen
     * @return true se CNPJ for matematicamente válido
     */
    public static boolean isValid(String raw) {
        if (raw == null) return false;

        String digits = raw.replaceAll("[^\\d]", "");

        if (digits.length() != 14) return false;

        // Rejeita sequências triviais (00000000000000, 11111111111111 …)
        if (digits.chars().distinct().count() == 1) return false;

        return checkDigit(digits, 12) && checkDigit(digits, 13);
    }

    /**
     * Remove formatação e retorna apenas os 14 dígitos.
     * Não valida — use isValid() antes.
     */
    public static String strip(String raw) {
        return raw == null ? null : raw.replaceAll("[^\\d]", "");
    }

    /**
     * Formata 14 dígitos no padrão XX.XXX.XXX/XXXX-XX.
     */
    public static String format(String digits) {
        if (digits == null || digits.length() != 14) return digits;
        return digits.substring(0, 2)  + "." +
               digits.substring(2, 5)  + "." +
               digits.substring(5, 8)  + "/" +
               digits.substring(8, 12) + "-" +
               digits.substring(12);
    }

    // ── Cálculo do dígito verificador ─────────────────────────────────────────

    private static boolean checkDigit(String digits, int position) {
        int[] weights = buildWeights(position);
        int sum = 0;
        for (int i = 0; i < position; i++) {
            sum += Character.getNumericValue(digits.charAt(i)) * weights[i];
        }
        int remainder = sum % 11;
        int expected  = remainder < 2 ? 0 : 11 - remainder;
        return Character.getNumericValue(digits.charAt(position)) == expected;
    }

    /**
     * Pesos para cálculo do dígito na posição dada.
     * Padrão Receita: ciclo descendente de 9 para 2, depois reinicia.
     */
    private static int[] buildWeights(int position) {
        int[] w = new int[position];
        int weight = 2;
        for (int i = position - 1; i >= 0; i--) {
            w[i]   = weight;
            weight = weight == 9 ? 2 : weight + 1;
        }
        return w;
    }
}
