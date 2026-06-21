package com.joao.cyberaudit.dto;

import com.joao.cyberaudit.model.Account;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class BrandingDto {

    /** Base64 do logo (PNG/JPG). Null = sem logo. */
    private String brandLogoBase64;

    /** Cor hex da marca (ex: "#00D3A3"). Null = cor padrão CyberAudit. */
    private String brandColor;

    /** Nome exibido no PDF. Null = "CYBERAUDIT". */
    private String brandReportName;

    public static BrandingDto from(Account a) {
        return new BrandingDto(
                a.getBrandLogoBase64(),
                a.getBrandColor(),
                a.getBrandReportName()
        );
    }
}
