package com.joao.cyberaudit.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

@Getter @Setter @NoArgsConstructor
public class TlsDetails {
    private String negotiatedProtocol;
    private String cipherSuite;
    private boolean weakProtocol;
    private String message;

    /**
     * Protocolos deprecados que o servidor AINDA aceita, além do negociado.
     *
     * O handshake sempre fecha no melhor protocolo (1.3), então este campo é a
     * única pista de que 1.0/1.1 continuam ligados. Sem ele, um servidor que
     * oferece 1.0 e 1.3 era reportado SECURE porque a negociação caía em 1.3 —
     * o ponto cego que este campo fecha.
     */
    private List<String> deprecatedProtocolsOffered = new ArrayList<>();

    /** Mantém compatível todo call site de 4 args (N/A, erros de inspeção, testes). */
    public TlsDetails(String negotiatedProtocol, String cipherSuite,
                      boolean weakProtocol, String message) {
        this(negotiatedProtocol, cipherSuite, weakProtocol, message, new ArrayList<>());
    }

    public TlsDetails(String negotiatedProtocol, String cipherSuite, boolean weakProtocol,
                      String message, List<String> deprecatedProtocolsOffered) {
        this.negotiatedProtocol = negotiatedProtocol;
        this.cipherSuite = cipherSuite;
        this.weakProtocol = weakProtocol;
        this.message = message;
        this.deprecatedProtocolsOffered =
                deprecatedProtocolsOffered == null ? new ArrayList<>() : deprecatedProtocolsOffered;
    }

    /**
     * O que nomear como fraco no laudo: os protocolos deprecados oferecidos, se
     * houver; senão o próprio negociado (caso em que o melhor já é fraco). Usado
     * pelo score para não estampar "TLS fraco: TLSv1.3" quando o problema é que
     * 1.0/1.1 seguem aceitos ao lado do 1.3.
     */
    public String getWeakProtocolLabel() {
        if (deprecatedProtocolsOffered != null && !deprecatedProtocolsOffered.isEmpty())
            return String.join(", ", deprecatedProtocolsOffered);
        return negotiatedProtocol;
    }
}
