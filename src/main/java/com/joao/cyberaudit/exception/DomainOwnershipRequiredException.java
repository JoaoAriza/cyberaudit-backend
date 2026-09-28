package com.joao.cyberaudit.exception;

import lombok.Getter;

/**
 * Scan ativo recusado porque o host não está registrado e verificado na conta
 * do usuário (ver {@code PlanLimitService.checkActiveScan}).
 *
 * Distinta de {@link OwnershipNotVerifiedException}: aquela é a checagem AO VIVO
 * do {@code .well-known/cyberaudit.txt} feita durante a execução do scan (vale
 * até para quem não tem conta); esta é a checagem de CADASTRO — o domínio precisa
 * existir como {@code Domain} verificado na conta antes mesmo de tentar escanear.
 * O remédio também difere: aqui o cliente resolve chamando {@code POST /domains}
 * e {@code POST /domains/{id}/verify}, não só reconferindo o arquivo.
 */
@Getter
public class DomainOwnershipRequiredException extends RuntimeException {

    private final String host;

    public DomainOwnershipRequiredException(String host, String message) {
        super(message);
        this.host = host;
    }
}
