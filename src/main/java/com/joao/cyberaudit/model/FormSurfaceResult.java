package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

/**
 * O que a página realmente coleta do visitante.
 *
 * Existe porque {@code inputSurfaceDetected} nunca respondeu essa pergunta: ele é
 * {@code hasQueryParams(url)}, ou seja, só olha se a URL tem "?". Uma vitrine com
 * {@code ?utm_source=face} marcava true, e uma página com formulário de contato
 * sem query marcava false. Para separar "site informativo" de "site que coleta
 * dado de cliente" — que é o que decide o impacto real de um achado — o sinal
 * tem de vir do HTML.
 *
 * Sai de graça: o fetch principal já baixa o corpo para extrair a CSP de
 * {@code <meta http-equiv>} e o descartava em seguida.
 */
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class FormSurfaceResult {

    /**
     * A página foi de fato lida: resposta 2xx com HTML.
     *
     * Falso quando o site bloqueou o scanner (403 de WAF), respondeu erro ou veio
     * sem corpo. Aí os campos abaixo em false NÃO querem dizer "não tem" — querem
     * dizer "não vi".
     */
    private boolean analyzed;

    /** Existe ao menos um {@code <form>}. Informativo: formulário de busca também é form. */
    private boolean hasForm;

    /** Existe campo de senha — indica área autenticada, não só contato. */
    private boolean hasPasswordField;

    /** Coleta dado pessoal: e-mail, telefone, CPF. Relevante para LGPD. */
    private boolean collectsPii;

    /** Campo de cartão (CVV, número, {@code autocomplete="cc-*"}). */
    private boolean hasPaymentField;

    /**
     * Casca de aplicação JavaScript: nenhum campo no HTML e a raiz vazia esperando o
     * script montar a tela. Os campos existem só depois de executar JS, e o scanner
     * não executa — então "sem campo" aqui também é "não vi".
     */
    private boolean jsRendered;

    /** Marcadores que casaram, para o laudo poder mostrar o porquê. */
    private List<String> evidence;

    /** Página sem corpo analisável — não é o mesmo que página sem formulário. */
    public static FormSurfaceResult vazio() {
        return FormSurfaceResult.builder().evidence(List.of()).build();
    }
}
