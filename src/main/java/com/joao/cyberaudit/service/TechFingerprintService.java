package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.TechFingerprintResult;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

@Service
public class TechFingerprintService {

    private final HttpClient client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.ALWAYS)
            .connectTimeout(Duration.ofSeconds(8))
            .build();

    /**
     * Detecta tecnologias usadas pelo site a partir de:
     * - Headers HTTP (Server, X-Powered-By, X-Generator, Via, etc.)
     * - Cookies (PHPSESSID, JSESSIONID, laravel_session, etc.)
     * - HTML body (meta tags, script patterns, data attributes)
     */
    public TechFingerprintResult fingerprint(String targetUrl,
                                             Map<String, String> analyzedHeaders,
                                             List<String> rawSetCookies) {
        List<String> evidence = new ArrayList<>();

        String webServer = null;
        String backend   = null;
        String framework = null;
        String cms       = null;
        String cdn       = null;
        String language  = null;
        List<String> libraries = new ArrayList<>();

        // ── 1. Headers HTTP ────────────────────────────────────────────────────

        // Server header
        String serverHeader = getRawHeader(targetUrl, "server");
        if (serverHeader != null) {
            String s = serverHeader.toLowerCase(Locale.ROOT);
            if (s.contains("nginx"))          { webServer = "nginx";   evidence.add("Server: " + serverHeader); }
            else if (s.contains("apache"))    { webServer = "Apache";  evidence.add("Server: " + serverHeader); }
            else if (s.contains("iis"))       { webServer = "IIS";     evidence.add("Server: " + serverHeader); }
            else if (s.contains("cloudflare")){ webServer = "Cloudflare"; cdn = "Cloudflare"; evidence.add("Server: cloudflare"); }
            else if (s.contains("lighttpd"))  { webServer = "Lighttpd"; evidence.add("Server: " + serverHeader); }
            else if (s.contains("openresty")) { webServer = "OpenResty (nginx)"; evidence.add("Server: " + serverHeader); }
            else if (s.contains("caddy"))     { webServer = "Caddy";   evidence.add("Server: " + serverHeader); }
            else if (!s.isBlank())            { webServer = serverHeader; evidence.add("Server: " + serverHeader); }
        }

        // X-Powered-By header
        String poweredBy = getRawHeader(targetUrl, "x-powered-by");
        if (poweredBy != null) {
            String p = poweredBy.toLowerCase(Locale.ROOT);
            evidence.add("X-Powered-By: " + poweredBy);
            if (p.contains("php"))            { language = "PHP";    backend = "PHP " + extractVersion(poweredBy); }
            else if (p.contains("asp.net"))   { language = "C#";     backend = "ASP.NET"; }
            else if (p.contains("express"))   { language = "Node.js"; framework = "Express"; }
            else if (p.contains("next.js"))   { language = "Node.js"; framework = "Next.js"; }
            else if (p.contains("java"))      { language = "Java"; }
        }

        // X-Generator
        String generator = getRawHeader(targetUrl, "x-generator");
        if (generator != null) {
            evidence.add("X-Generator: " + generator);
            String g = generator.toLowerCase(Locale.ROOT);
            if (g.contains("wordpress")) cms = "WordPress";
            else if (g.contains("drupal")) cms = "Drupal";
            else if (g.contains("joomla")) cms = "Joomla";
        }

        // Via header (CDN/proxy)
        String via = getRawHeader(targetUrl, "via");
        if (via != null) {
            String v = via.toLowerCase(Locale.ROOT);
            evidence.add("Via: " + via);
            if (v.contains("cloudfront"))     cdn = "AWS CloudFront";
            else if (v.contains("varnish"))   cdn = "Varnish";
            else if (v.contains("squid"))     cdn = "Squid";
        }

        // CDN-specific headers
        String cfRay = getRawHeader(targetUrl, "cf-ray");
        if (cfRay != null) { cdn = "Cloudflare"; evidence.add("cf-ray header presente"); }

        String xServedBy = getRawHeader(targetUrl, "x-served-by");
        if (xServedBy != null && xServedBy.toLowerCase().contains("cache")) {
            cdn = "Fastly"; evidence.add("x-served-by: " + xServedBy);
        }

        String xAmzId = getRawHeader(targetUrl, "x-amz-id-2");
        if (xAmzId != null) { cdn = "AWS S3/CloudFront"; evidence.add("x-amz-id-2 header presente"); }

        String xVercel = getRawHeader(targetUrl, "x-vercel-id");
        if (xVercel != null) { cdn = "Vercel"; evidence.add("x-vercel-id header presente"); }

        String xNetlify = getRawHeader(targetUrl, "x-nf-request-id");
        if (xNetlify != null) { cdn = "Netlify"; evidence.add("x-nf-request-id header presente"); }

        // ── 2. Cookies ─────────────────────────────────────────────────────────
        if (rawSetCookies != null) {
            for (String cookie : rawSetCookies) {
                String cl = cookie.toLowerCase(Locale.ROOT);
                if (cl.startsWith("phpsessid"))           { language = "PHP"; evidence.add("Cookie: PHPSESSID"); }
                else if (cl.startsWith("jsessionid"))     { language = "Java"; backend = "Java Servlet/Tomcat"; evidence.add("Cookie: JSESSIONID"); }
                else if (cl.startsWith("laravel_session")){ language = "PHP"; framework = "Laravel"; evidence.add("Cookie: laravel_session"); }
                else if (cl.startsWith("wp-settings") || cl.startsWith("wordpress_"))
                { cms = "WordPress"; evidence.add("Cookie: WordPress session"); }
                else if (cl.startsWith("django"))        { language = "Python"; framework = "Django"; evidence.add("Cookie: Django session"); }
                else if (cl.startsWith("rack.session"))  { language = "Ruby"; framework = "Rails/Rack"; evidence.add("Cookie: rack.session"); }
                else if (cl.startsWith("_rails"))        { language = "Ruby"; framework = "Ruby on Rails"; evidence.add("Cookie: _rails"); }
                else if (cl.startsWith("craft"))         { cms = "Craft CMS"; evidence.add("Cookie: Craft CMS"); }
                else if (cl.startsWith("typo3"))         { cms = "TYPO3"; evidence.add("Cookie: TYPO3"); }
                else if (cl.startsWith("express:sess"))  { language = "Node.js"; framework = "Express"; evidence.add("Cookie: Express session"); }
            }
        }

        // ── 3. HTML body ────────────────────────────────────────────────────────
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(targetUrl))
                    .GET()
                    .timeout(Duration.ofSeconds(10))
                    .header("User-Agent", "Mozilla/5.0 CyberAuditScanner/1.0")
                    .header("Accept", "text/html")
                    .build();

            HttpResponse<String> resp = client.send(req,
                    HttpResponse.BodyHandlers.ofString());
            String body = resp.body() == null ? "" : resp.body();
            String lower = body.toLowerCase(Locale.ROOT);

            // CMS detection via meta/body
            if (lower.contains("/wp-content/") || lower.contains("/wp-includes/")) {
                cms = "WordPress"; evidence.add("HTML: /wp-content/ path detectado");
            } else if (lower.contains("drupal.settings") || lower.contains("/sites/default/files/")) {
                cms = "Drupal"; evidence.add("HTML: Drupal signature detectada");
            } else if (lower.contains("joomla") || lower.contains("/components/com_")) {
                cms = "Joomla"; evidence.add("HTML: Joomla signature detectada");
            } else if (lower.contains("shopify.com/s/files") || lower.contains("cdn.shopify.com")) {
                cms = "Shopify"; evidence.add("HTML: Shopify CDN detectado");
            } else if (lower.contains("ghost-url") || lower.contains("/ghost/api/")) {
                cms = "Ghost"; evidence.add("HTML: Ghost CMS detectado");
            } else if (lower.contains("webflow.com") || lower.contains("webflow-badge")) {
                cms = "Webflow"; evidence.add("HTML: Webflow detectado");
            }

            // Meta generator
            int genIdx = lower.indexOf("<meta name=\"generator\"");
            if (genIdx >= 0) {
                String meta = body.substring(genIdx, Math.min(genIdx + 150, body.length()));
                String metaLower = meta.toLowerCase();
                evidence.add("Meta generator: " + meta.replaceAll("\\s+", " ").trim());
                if (metaLower.contains("wordpress")) cms = "WordPress";
                else if (metaLower.contains("drupal")) cms = "Drupal";
                else if (metaLower.contains("joomla")) cms = "Joomla";
                else if (metaLower.contains("ghost")) cms = "Ghost";
                else if (metaLower.contains("wix")) cms = "Wix";
                else if (metaLower.contains("squarespace")) cms = "Squarespace";
            }

            // Framework detection via JS patterns
            if (lower.contains("__next_data__") || lower.contains("_next/static")) {
                framework = "Next.js"; language = coalesce(language, "Node.js");
                evidence.add("HTML: __NEXT_DATA__ / _next/static");
            } else if (lower.contains("nuxt") && lower.contains("__nuxt")) {
                framework = "Nuxt.js"; language = coalesce(language, "Node.js");
                evidence.add("HTML: __nuxt signature");
            } else if (lower.contains("ng-version") || lower.contains("ng-app")) {
                framework = "Angular"; language = coalesce(language, "TypeScript");
                evidence.add("HTML: Angular directive detectada");
            } else if (lower.contains("data-reactroot") || lower.contains("__reactfiber")) {
                libraries.add("React"); evidence.add("HTML: React fiber detectado");
            } else if (lower.contains("vue.js") || lower.contains("__vue_app__") || lower.contains("data-v-app")) {
                libraries.add("Vue.js"); evidence.add("HTML: Vue.js detectado");
            } else if (lower.contains("svelte-") || lower.contains("__svelte")) {
                libraries.add("Svelte"); evidence.add("HTML: Svelte detectado");
            }

            // Libraries
            if (lower.contains("jquery")) {
                libraries.add("jQuery"); evidence.add("HTML: jQuery detectado");
            }
            if (lower.contains("bootstrap")) {
                libraries.add("Bootstrap"); evidence.add("HTML: Bootstrap detectado");
            }
            if (lower.contains("tailwindcss") || lower.contains("tw-")) {
                libraries.add("Tailwind CSS"); evidence.add("HTML: Tailwind CSS detectado");
            }

            // Backend via inline patterns
            if (lower.contains("laravel") && framework == null) {
                framework = "Laravel"; language = coalesce(language, "PHP");
                evidence.add("HTML: Laravel signature");
            }
            if (lower.contains("asp.net_sessionid") || lower.contains("__viewstate")) {
                backend = "ASP.NET"; language = coalesce(language, "C#");
                evidence.add("HTML: ASP.NET ViewState detectado");
            }
            if (lower.contains("thymeleaf") || lower.contains("th:text")) {
                framework = "Spring + Thymeleaf"; language = coalesce(language, "Java");
                evidence.add("HTML: Thymeleaf template detectado");
            }
            if (lower.contains("inertia") && lower.contains("data-page")) {
                libraries.add("Inertia.js"); evidence.add("HTML: Inertia.js detectado");
            }

        } catch (Exception ignored) {}

        return TechFingerprintResult.builder()
                .webServer(webServer)
                .backend(backend)
                .framework(framework)
                .cms(cms)
                .cdn(cdn)
                .language(language)
                .libraries(libraries)
                .evidence(evidence)
                .build();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Faz uma requisição HEAD/GET e retorna o valor do header solicitado.
     * Usa o HttpClient com redirect para garantir que pegamos headers do destino final.
     */
    private String getRawHeader(String url, String headerName) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .method("HEAD", HttpRequest.BodyPublishers.noBody())
                    .timeout(Duration.ofSeconds(6))
                    .header("User-Agent", "Mozilla/5.0 CyberAuditScanner/1.0")
                    .build();
            HttpResponse<Void> resp = client.send(req, HttpResponse.BodyHandlers.discarding());
            return resp.headers().firstValue(headerName).orElse(null);
        } catch (Exception e) {
            return null;
        }
    }

    private String extractVersion(String value) {
        // Extrai versão de strings como "PHP/8.1.2"
        int slash = value.indexOf('/');
        if (slash >= 0 && slash < value.length() - 1)
            return value.substring(slash + 1).trim();
        return value.trim();
    }

    private String coalesce(String existing, String fallback) {
        return existing != null ? existing : fallback;
    }
}