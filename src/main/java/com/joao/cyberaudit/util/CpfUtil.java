package com.joao.cyberaudit.util;

/**
 * Utilitário para validação e formatação de CPF.
 *
 * Algoritmo: módulo 11 com dois dígitos verificadores (Receita Federal).
 * Referência: https://www.receita.fazenda.gov.br/aplicacoes/atcta/cpf/orientacoes.htm
 */
public final class CpfUtil {

    private CpfUtil() {}

    /**
     * Valida um CPF (aceita com ou sem máscara).
     *
     * @param raw string bruta — pode conter pontos e hífen
     * @return true se CPF for matematicamente válido
     */
    public static boolean isValid(String raw) {
        if (raw == null) return false;

        String digits = raw.replaceAll("[^\\d]", "");

        if (digits.length() != 11) return false;

        // Rejeita sequências triviais (00000000000, 11111111111 …) — passam no módulo 11
        // mas nunca foram emitidas pela Receita.
        if (digits.chars().distinct().count() == 1) return false;

        return checkDigit(digits, 9) && checkDigit(digits, 10);
    }

    /**
     * Remove formatação e retorna apenas os 11 dígitos.
     * Não valida — use isValid() antes.
     */
    public static String strip(String raw) {
        return raw == null ? null : raw.replaceAll("[^\\d]", "");
    }

    /**
     * Formata 11 dígitos no padrão XXX.XXX.XXX-XX.
     */
    public static String format(String digits) {
        if (digits == null || digits.length() != 11) return digits;
        return digits.substring(0, 3) + "." +
               digits.substring(3, 6) + "." +
               digits.substring(6, 9) + "-" +
               digits.substring(9);
    }

    // ── Cálculo do dígito verificador ─────────────────────────────────────────

    /**
     * Pesos do CPF descem direto de (position+1) até 2, sem o reinício em 9 do
     * CNPJ — por isso não reaproveita {@link CnpjUtil}, cujos pesos nunca passam de 9.
     */
    private static boolean checkDigit(String digits, int position) {
        int sum = 0;
        int weight = position + 1;
        for (int i = 0; i < position; i++) {
            sum += Character.getNumericValue(digits.charAt(i)) * weight--;
        }
        int remainder = sum % 11;
        int expected  = remainder < 2 ? 0 : 11 - remainder;
        return Character.getNumericValue(digits.charAt(position)) == expected;
    }
}
