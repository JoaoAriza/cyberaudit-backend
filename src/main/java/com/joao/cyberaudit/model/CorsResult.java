package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class CorsResult {

    private boolean tested;
    private String allowOriginValue;
    private boolean wildcardOrigin;
    private boolean reflectsOrigin;
    private boolean isCredentialsAllowed;
    private boolean nullOriginAccepted;
    private String message;

}
