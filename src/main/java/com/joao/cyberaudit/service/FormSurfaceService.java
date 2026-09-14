package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.FormSurfaceResult;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Lê no HTML o que a página coleta do visitante.
 *
 * Função pura sobre o corpo que o {@link HttpFetchService} já tem em mãos —
 * nenhuma requisição adicional. Só por isso ela pode existir: um módulo novo com
 * request próprio não se pagaria para responder "tem formulário?".
 */
@Service
public class FormSurfaceService {

    /** {@code <form}, tolerando {@code <form>} e {@code <form ...>}. */
    private static final Pattern FORM = Pattern.compile("<form[\\s>]", Pattern.CASE_INSENSITIVE);

    /**
     * O atributo {@code type}, e não a palavra solta: uma página que fala
     * "senha" no texto não tem campo de senha.
     */
    private static final Pattern PASSWORD = Pattern.compile(
            "type\\s*=\\s*[\"']?password", Pattern.CASE_INSENSITIVE);

    private static final Pattern PII_TYPE = Pattern.compile(
            "type\\s*=\\s*[\"']?(email|tel)\\b", Pattern.CASE_INSENSITIVE);

    /** Campos brasileiros comuns, por name/id — cobre form que usa type="text". */
    private static final Pattern PII_NOME = Pattern.compile(
            "(name|id)\\s*=\\s*[\"'][^\"']*(cpf|cnpj|telefone|celular|whatsapp|e-?mail)[^\"']*[\"']",
            Pattern.CASE_INSENSITIVE);

    /**
     * {@code autocomplete="cc-*"} é o marcador padrão do HTML para cartão e o
     * sinal mais limpo; CVV/CVC cobrem quem não usa o atributo.
     */
    private static final Pattern PAGAMENTO = Pattern.compile(
            "autocomplete\\s*=\\s*[\"']cc-|\\b(cvv|cvc)\\b|(name|id)\\s*=\\s*[\"'][^\"']*"
            + "(card[-_]?number|numero[-_]?cartao|cartao[-_]?numero)[^\"']*[\"']",
            Pattern.CASE_INSENSITIVE);

    public FormSurfaceResult analyze(String html) {
        if (html == null || html.isBlank()) return FormSurfaceResult.vazio();

        List<String> evidence = new ArrayList<>();

        boolean form     = FORM.matcher(html).find();
        boolean senha    = PASSWORD.matcher(html).find();
        boolean pii      = PII_TYPE.matcher(html).find() || PII_NOME.matcher(html).find();
        boolean pagamento = PAGAMENTO.matcher(html).find();

        if (form)      evidence.add("form");
        if (senha)     evidence.add("password-field");
        if (pii)       evidence.add("pii-field");
        if (pagamento) evidence.add("payment-field");

        return FormSurfaceResult.builder()
                .hasForm(form)
                .hasPasswordField(senha)
                .collectsPii(pii)
                .hasPaymentField(pagamento)
                .evidence(List.copyOf(evidence))
                .build();
    }
}
