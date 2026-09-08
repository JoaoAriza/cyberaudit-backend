package com.joao.cyberaudit.dto;

import lombok.Data;

/**
 * @param timezone identificador IANA, como {@code America/Sao_Paulo}
 * @param manual   true quando veio do seletor do perfil; false quando é a detecção
 *                 automática do navegador, que não sobrepõe escolha explícita
 */
@Data
public class TimeZoneRequest {
    private String  timezone;
    private boolean manual;
}
