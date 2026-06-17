package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter @Setter @AllArgsConstructor @NoArgsConstructor
public class TlsDetails {
    private String negotiatedProtocol;
    private String cipherSuite;
    private boolean weakProtocol;
    private String message;
}
