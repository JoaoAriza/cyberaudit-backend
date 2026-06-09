package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class WafDetectionResult {

    private boolean detected;
    private String provider;
    /**
     * "WAF"  — proteção ativa contra ataques (Cloudflare, AWS WAF, Imperva, Sucuri, Akamai, F5, Barracuda)
     * "CDN"  — infraestrutura de entrega sem WAF por padrão (Vercel, GitHub, Google Cloud, Fastly, Varnish)
     * "BOTH" — CDN que inclui capacidade WAF configurável (Azure Front Door, AWS CloudFront)
     * null   — não detectado
     */
    private String category;
    private String confidence;
    private String evidence;
    private String probeResponse;
    private String summary;
}