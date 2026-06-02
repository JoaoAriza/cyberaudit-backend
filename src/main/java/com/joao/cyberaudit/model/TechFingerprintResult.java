package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TechFingerprintResult {

    private String       webServer;        // nginx, Apache, IIS
    private String       backend;          // PHP, Java, ASP.NET, Node.js
    private String       framework;        // Laravel, Spring, Django, Next.js
    private String       cms;             // WordPress, Drupal, Joomla
    private String       cdn;             // Cloudflare, Fastly, Akamai
    private String       language;        // PHP, Java, Python, Ruby
    private List<String> libraries;       // React, Vue, jQuery, Bootstrap
    private List<String> evidence;        // evidências técnicas das detecções

    /**
     * Mapa software → versão detectada.
     * Só populado quando a versão é identificável nos headers ou HTML.
     * Usado pelo CVECorrelationService para queries direcionadas na NVD.
     *
     * Exemplos:
     *   "Apache HTTP Server" → "2.4.49"
     *   "PHP"               → "8.1.2"
     *   "nginx"             → "1.18.0"
     *   "OpenSSL"           → "1.1.1k"
     */
    private Map<String, String> detectedVersions;
}