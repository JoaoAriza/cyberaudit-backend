package com.joao.cyberaudit.dto;

import com.joao.cyberaudit.model.Domain;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
public class DomainDto {

    private UUID          id;
    private String        host;
    private boolean       verified;
    private LocalDateTime verifiedAt;
    private LocalDateTime createdAt;
    /** Token de verificação — sempre derivado deterministicamente do host */
    private String        verificationToken;

    public static DomainDto from(Domain d, String verificationToken) {
        DomainDto dto = new DomainDto();
        dto.setId(d.getId());
        dto.setHost(d.getHost());
        dto.setVerified(d.isVerified());
        dto.setVerifiedAt(d.getVerifiedAt());
        dto.setCreatedAt(d.getCreatedAt());
        dto.setVerificationToken(verificationToken);
        return dto;
    }
}
