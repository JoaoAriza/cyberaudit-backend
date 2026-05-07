package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class TlsDetails {
    private String negotiatedProtocol;
    private String cipherSuite;
    private boolean weakProtocol;
    private String message;
}
