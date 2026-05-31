package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TechFingerprintResult {

    private String webServer;       // nginx, Apache, IIS, cloudflare
    private String backend;         // PHP, Java, ASP.NET, Node.js, Python
    private String framework;       // Laravel, Spring, Django, Next.js, Nuxt
    private String cms;             // WordPress, Drupal, Joomla, Ghost
    private String cdn;             // Cloudflare, Fastly, Akamai, AWS CloudFront
    private String language;        // PHP, Java, Python, Ruby, Go
    private List<String> libraries; // React, Vue, Angular, jQuery, Bootstrap
    private List<String> evidence;  // lista de evidências que levaram às detecções
}