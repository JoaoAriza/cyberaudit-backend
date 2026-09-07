package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter @Setter @Builder @NoArgsConstructor @AllArgsConstructor
public class DnsSecurityResult {

    private boolean spfPresent;
    private String spfRecord;
    private String spfPolicy;

    private boolean dmarcPresent;
    private String  dmarcRecord;
    private String  dmarcPolicy;

    private boolean dkimHintFound;
    private String  dkimSelector;

    private boolean caaPresent;
    private String  caaRecord;

    /**
     * Todos os registros CAA do domínio, não só o primeiro.
     *
     * `caaRecord` guarda um registro só e é o que a UI exibe. Usá-lo para
     * decidir se um emissor é autorizado comparava o certificado contra uma
     * única CA de uma lista que costuma ter seis ou mais — num domínio com
     * `issue "comodoca.com"` na frente, certificados legítimos de Let's Encrypt
     * apareciam como violação de CAA.
     */
    private List<String> caaRecords;

    private boolean mxPresent;
    private List<String> mxRecords;

    private String emailSpoofingRisk;
    private String summary;

    /**
     * Alguma consulta falhou por rede, não por ausência de registro.
     *
     * Sem esta distinção, "não encontrei o registro" e "não consegui perguntar"
     * produziam exatamente o mesmo laudo — e o segundo caso vinha marcado como
     * módulo OK. Foi assim que um bloqueio de UDP/53 no host fez todo domínio
     * escaneado, inclusive google.com, aparecer sem SPF, DMARC, DKIM e CAA.
     *
     * Um scanner de segurança não pode afirmar ausência quando falhou em olhar.
     */
    private boolean lookupFailed;
}
