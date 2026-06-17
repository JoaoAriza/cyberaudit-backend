package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter @Setter @AllArgsConstructor @NoArgsConstructor
public class CorsResult {
    private boolean tested;
    private String allowOriginValue;
    private boolean wildcardOrigin;
    private boolean reflectsOrigin;
    private boolean isCredentialsAllowed;
    private boolean nullOriginAccepted;
    private String message;
}
