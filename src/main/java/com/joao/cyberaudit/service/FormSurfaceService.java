package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.FormSurfaceResult;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Lê no HTML o que a página coleta do visitante.
 *
 * Função pura sobre o corpo que o {@link HttpFetchService} já tem em mãos —
 * nenhuma requisição adicional. Só por isso ela pode existir: um módulo novo com
 * request próprio não se pagaria para responder "tem formulário?".
 *
 * O sinal mora nos CAMPOS de entrada ({@code input}, {@code select},
 * {@code textarea}), e não em atributo ou palavra solta no HTML. A primeira versão
 * olhava o documento inteiro: {@code id="whatsapp-float"} num botão virava campo de
 * telefone, "CVV" num parágrafo de ajuda virava campo de cartão e
 * {@code data-type="password"} virava senha.
 */
@Service
public class FormSurfaceService {

    private static final int FLAGS = Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE;

    /** {@code <form}, tolerando {@code <form>} e {@code <form ...>}. */
    private static final Pattern FORM = Pattern.compile("<form[\\s>]", FLAGS);

    /** Um elemento de entrada inteiro, da abertura ao {@code >}. */
    private static final Pattern CAMPO = Pattern.compile("<(input|select|textarea)\\b[^>]*>", FLAGS);

    /**
     * Tipos que não recebem dado digitado pelo visitante. {@code search} entra aqui:
     * caixa de busca não é coleta, e costuma ser o único campo de uma vitrine.
     */
    private static final Set<String> TIPOS_SEM_DADO = Set.of(
            "hidden", "submit", "button", "reset", "image", "checkbox", "radio",
            "range", "color", "file", "search");

    /** Dado pessoal por name/id/placeholder — cobre o campo que usa type="text". */
    private static final Pattern PII = Pattern.compile(
            "cpf|cnpj|telefone|celular|whatsapp|phone|e-?mail", FLAGS);

    /** Número e código de segurança do cartão por name/id/placeholder. */
    private static final Pattern CARTAO = Pattern.compile(
            "card[-_ ]?number|cc[-_]?num|n[uú]mero[-_ ]?(do[-_ ]?)?cart[aã]o|cart[aã]o[-_]?numero|cvv|cvc",
            FLAGS);

    /**
     * Rótulo de campo de cartão — só dentro de {@code <label>}, nunca em texto
     * corrido, e só vale quando a página tem algum campo.
     */
    private static final Pattern ROTULO_CARTAO = Pattern.compile(
            "<label\\b[^>]*>[^<]{0,60}(cvv|cvc|n[uú]mero do cart[aã]o)", FLAGS);

    /** Raiz vazia de aplicação React/Vue/Angular esperando o JavaScript montar a tela. */
    private static final Pattern RAIZ_SPA = Pattern.compile(
            "<div\\b[^>]*(?<=\\s)id\\s*=\\s*[\"'](root|app)[\"'][^>]*>\\s*</div>"
            + "|<app-root\\b[^>]*>\\s*</app-root>", FLAGS);

    /**
     * Atributos lidos de cada campo. O nome tem de vir depois de espaço ou aspas,
     * para {@code data-type} não ser lido como {@code type}.
     */
    private static final Map<String, Pattern> ATRIBUTOS = Map.of(
            "type",         atributo("type"),
            "name",         atributo("name"),
            "id",           atributo("id"),
            "placeholder",  atributo("placeholder"),
            "autocomplete", atributo("autocomplete"));

    private static Pattern atributo(String nome) {
        return Pattern.compile(
                "(?<=[\\s\"'])" + nome + "\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s>]+))", FLAGS);
    }

    public FormSurfaceResult analyze(String html) {
        if (html == null || html.isBlank()) return FormSurfaceResult.vazio();

        boolean form = FORM.matcher(html).find();
        boolean senha = false, pii = false, pagamento = false;
        int campos = 0;

        Matcher m = CAMPO.matcher(html);
        while (m.find()) {
            String tag  = m.group();
            String tipo = "input".equalsIgnoreCase(m.group(1))
                    ? valor(tag, "type").orElse("text").toLowerCase(Locale.ROOT)
                    : "";
            if (TIPOS_SEM_DADO.contains(tipo)) continue;
            campos++;

            String autocomplete = valor(tag, "autocomplete").orElse("").toLowerCase(Locale.ROOT);
            String identidade   = valor(tag, "name").orElse("") + " " + valor(tag, "id").orElse("")
                    + " " + valor(tag, "placeholder").orElse("");

            if ("password".equals(tipo)) senha = true;
            if (autocomplete.startsWith("cc-") || CARTAO.matcher(identidade).find()) pagamento = true;
            if ("email".equals(tipo) || "tel".equals(tipo)
                    || "email".equals(autocomplete) || autocomplete.startsWith("tel")
                    || PII.matcher(identidade).find()) pii = true;
        }
        if (campos > 0 && ROTULO_CARTAO.matcher(html).find()) pagamento = true;
        boolean jsRendered = campos == 0 && RAIZ_SPA.matcher(html).find();

        List<String> evidence = new ArrayList<>();
        if (form)       evidence.add("form");
        if (senha)      evidence.add("password-field");
        if (pii)        evidence.add("pii-field");
        if (pagamento)  evidence.add("payment-field");
        if (jsRendered) evidence.add("js-rendered");

        return FormSurfaceResult.builder()
                .analyzed(true)
                .hasForm(form)
                .hasPasswordField(senha)
                .collectsPii(pii)
                .hasPaymentField(pagamento)
                .jsRendered(jsRendered)
                .evidence(List.copyOf(evidence))
                .build();
    }

    private static Optional<String> valor(String tag, String atributo) {
        Matcher m = ATRIBUTOS.get(atributo).matcher(tag);
        if (!m.find()) return Optional.empty();
        for (int g = 1; g <= 3; g++) {
            if (m.group(g) != null) return Optional.of(m.group(g));
        }
        return Optional.empty();
    }
}
