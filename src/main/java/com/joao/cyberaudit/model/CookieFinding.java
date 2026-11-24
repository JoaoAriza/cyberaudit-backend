package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter @Setter @AllArgsConstructor @NoArgsConstructor
public class CookieFinding {
    private String name;
    private boolean httpOnly;
    private boolean secure;
    private String sameSite;
    private String risk;
    private String issues;
    /**
     * Códigos dos problemas que o card lista, na ordem de {@code issues}. São as chaves
     * do catálogo: {@code COOKIE_SEM_SECURE}, {@code COOKIE_SEM_HTTPONLY},
     * {@code COOKIE_SEM_SAMESITE} e {@code COOKIE_SAMESITE_NONE_SEM_SECURE}.
     *
     * Quem precisa saber o que está errado no cookie (o compliance, a tela) lê daqui, em
     * vez de refazer a conta pelas flags. Refazendo, cada um errava de um jeito (BUG-13).
     * Vem nulo em scan gravado antes de o campo existir.
     */
    private List<String> problems;
}
