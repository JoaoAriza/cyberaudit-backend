package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.TechFingerprintResult;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class TechFingerprintService {

    private static final Pattern VERSION_PATTERN =
            Pattern.compile("(\\d+\\.\\d+(?:\\.\\d+)?)");

    private final HttpClient client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.ALWAYS)
            .connectTimeout(Duration.ofSeconds(8))
            .build();

    public TechFingerprintResult fingerprint(String targetUrl,
                                             Map<String, String> analyzedHeaders,
                                             List<String> rawSetCookies) {
        List<String>        evidence         = new ArrayList<>();
        Map<String, String> detectedVersions = new LinkedHashMap<>();

        String webServer = null;
        String backend   = null;
        String framework = null;
        String cms       = null;
        String cdn       = null;
        String language  = null;
        List<String> libraries = new ArrayList<>();

        // ── 1. Headers HTTP ────────────────────────────────────────────────────

        String serverHeader = getRawHeader(targetUrl, "server");
        if (serverHeader != null) {
            String s = serverHeader.toLowerCase(Locale.ROOT);
            evidence.add("Server: " + serverHeader);

            if (s.contains("cloudflare")) {
                webServer = "Cloudflare"; cdn = "Cloudflare";
            } else if (s.contains("apache")) {
                String v = extractVersion(serverHeader).orElse(null);
                webServer = v != null ? "Apache HTTP Server " + v : "Apache HTTP Server";
                if (v != null) detectedVersions.put("Apache HTTP Server", v);
            } else if (s.contains("nginx")) {
                String v = extractVersion(serverHeader).orElse(null);
                webServer = v != null ? "nginx " + v : "nginx";
                if (v != null) detectedVersions.put("nginx", v);

            } else if (s.contains("microsoft-iis") || s.contains("iis")) {
                String v = extractVersion(serverHeader).orElse(null);
                webServer = v != null ? "Microsoft IIS " + v : "Microsoft IIS";
                if (v != null) detectedVersions.put("Microsoft IIS", v);
            } else if (s.contains("lighttpd")) {
                webServer = "Lighttpd";
                extractVersion(serverHeader).ifPresent(v -> detectedVersions.put("Lighttpd", v));
            } else if (s.contains("openresty")) {
                webServer = "OpenResty (nginx)";
                extractVersion(serverHeader).ifPresent(v -> detectedVersions.put("OpenResty", v));
            } else if (s.contains("caddy")) {
                webServer = "Caddy";
            } else if (!s.isBlank()) {
                webServer = serverHeader;
            }
        }

        // X-Powered-By
        String poweredBy = getRawHeader(targetUrl, "x-powered-by");
        if (poweredBy != null) {
            String p = poweredBy.toLowerCase(Locale.ROOT);
            evidence.add("X-Powered-By: " + poweredBy);

            if (p.contains("php")) {
                language = "PHP";
                String version = extractVersion(poweredBy).orElse(null);
                backend = version != null ? "PHP " + version : "PHP";
                if (version != null) detectedVersions.put("PHP", version);
            } else if (p.contains("asp.net")) {
                language = "C#"; backend = "ASP.NET";
                extractVersion(poweredBy).ifPresent(v -> detectedVersions.put("ASP.NET", v));
            } else if (p.contains("express")) {
                language = "Node.js"; framework = "Express";
                extractVersion(poweredBy).ifPresent(v -> detectedVersions.put("Express", v));
            } else if (p.contains("next.js")) {
                language = "Node.js"; framework = "Next.js";
                extractVersion(poweredBy).ifPresent(v -> detectedVersions.put("Next.js", v));
            }
        }

        // X-Generator
        String generator = getRawHeader(targetUrl, "x-generator");
        if (generator != null) {
            evidence.add("X-Generator: " + generator);
            String g = generator.toLowerCase(Locale.ROOT);
            if      (g.contains("wordpress")) { cms = "WordPress"; extractVersion(generator).ifPresent(v -> detectedVersions.put("WordPress", v)); }
            else if (g.contains("drupal"))    { cms = "Drupal";    extractVersion(generator).ifPresent(v -> detectedVersions.put("Drupal", v)); }
            else if (g.contains("joomla"))    { cms = "Joomla";    extractVersion(generator).ifPresent(v -> detectedVersions.put("Joomla", v)); }
        }

        // CDN-specific headers
        String cfRay = getRawHeader(targetUrl, "cf-ray");
        if (cfRay != null)    { cdn = "Cloudflare"; evidence.add("cf-ray header presente"); }

        String xServedBy = getRawHeader(targetUrl, "x-served-by");
        if (xServedBy != null && xServedBy.toLowerCase().contains("cache")) {
            cdn = "Fastly"; evidence.add("x-served-by: " + xServedBy);
        }

        String via = getRawHeader(targetUrl, "via");
        if (via != null) {
            evidence.add("Via: " + via);
            String v = via.toLowerCase(Locale.ROOT);
            if      (v.contains("cloudfront")) cdn = "AWS CloudFront";
            else if (v.contains("varnish"))    cdn = "Varnish";
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
                if      (cl.startsWith("phpsessid"))            { language = "PHP";    evidence.add("Cookie: PHPSESSID"); }
                else if (cl.startsWith("jsessionid"))           { language = "Java";   backend = coalesce(backend, "Java Servlet/Tomcat"); evidence.add("Cookie: JSESSIONID"); }
                else if (cl.startsWith("laravel_session"))      { language = "PHP";    framework = "Laravel"; evidence.add("Cookie: laravel_session"); }
                else if (cl.startsWith("wp-settings") || cl.startsWith("wordpress_")) { cms = "WordPress"; evidence.add("Cookie: WordPress session"); }
                else if (cl.startsWith("django"))               { language = "Python"; framework = "Django"; evidence.add("Cookie: Django session"); }
                else if (cl.startsWith("_rails") || cl.startsWith("rack.session")) { language = "Ruby"; framework = "Ruby on Rails"; evidence.add("Cookie: Rails/Rack session"); }
                else if (cl.startsWith("craft"))                { cms = "Craft CMS";  evidence.add("Cookie: Craft CMS"); }
                else if (cl.startsWith("express:sess"))         { language = "Node.js"; framework = coalesce(framework, "Express"); evidence.add("Cookie: Express session"); }
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

            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
            String body  = resp.body() == null ? "" : resp.body();
            String lower = body.toLowerCase(Locale.ROOT);

            // CMS via paths
            if (lower.contains("/wp-content/") || lower.contains("/wp-includes/")) {
                cms = "WordPress"; evidence.add("HTML: /wp-content/ path detectado");
                extractWpVersion(body).ifPresent(v -> detectedVersions.put("WordPress", v));
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

            // Meta generator (contém versão do CMS frequentemente)
            int genIdx = lower.indexOf("<meta name=\"generator\"");
            if (genIdx >= 0) {
                String meta = body.substring(genIdx, Math.min(genIdx + 200, body.length()));
                evidence.add("Meta generator: " + meta.replaceAll("[\\r\\n]+", " ").trim());
                String metaLower = meta.toLowerCase(Locale.ROOT);
                if (metaLower.contains("wordpress")) {
                    cms = "WordPress";
                    extractVersion(meta).ifPresent(v -> detectedVersions.put("WordPress", v));
                } else if (metaLower.contains("drupal")) {
                    cms = "Drupal";
                    extractVersion(meta).ifPresent(v -> detectedVersions.put("Drupal", v));
                } else if (metaLower.contains("joomla")) {
                    cms = "Joomla";
                    extractVersion(meta).ifPresent(v -> detectedVersions.put("Joomla", v));
                }
            }

            // Frameworks JS
            if (lower.contains("__next_data__") || lower.contains("_next/static")) {
                framework = "Next.js"; language = coalesce(language, "Node.js");
                evidence.add("HTML: __NEXT_DATA__ / _next/static");
            } else if (lower.contains("__nuxt") || lower.contains("data-n-head")) {
                framework = "Nuxt.js"; language = coalesce(language, "Node.js");
                evidence.add("HTML: Nuxt.js signature");
            } else if (lower.contains("ng-version") || lower.contains("ng-app")) {
                framework = "Angular"; language = coalesce(language, "TypeScript");
                evidence.add("HTML: Angular directive detectada");
                // ng-version="15.2.0" tem a versão
                extractNgVersion(body).ifPresent(v -> detectedVersions.put("Angular", v));
            } else if (lower.contains("data-reactroot") || lower.contains("__reactfiber")) {
                libraries.add("React"); evidence.add("HTML: React fiber detectado");
            } else if (lower.contains("vue.js") || lower.contains("__vue_app__") || lower.contains("data-v-app")) {
                libraries.add("Vue.js"); evidence.add("HTML: Vue.js detectado");
            } else if (lower.contains("svelte-") || lower.contains("__svelte")) {
                libraries.add("Svelte"); evidence.add("HTML: Svelte detectado");
            }

            // Libraries
            if (lower.contains("jquery")) {
                String jqVersion = extractJQueryVersion(body).orElse(null);
                libraries.add(jqVersion != null ? "jQuery " + jqVersion : "jQuery");
                evidence.add("HTML: jQuery detectado");
                if (jqVersion != null) detectedVersions.put("jQuery", jqVersion);
            }
            if (lower.contains("bootstrap")) { libraries.add("Bootstrap"); evidence.add("HTML: Bootstrap detectado"); }
            if (lower.contains("tailwindcss") || lower.contains("tw-")) { libraries.add("Tailwind CSS"); evidence.add("HTML: Tailwind CSS detectado"); }

            // Backend patterns
            if (lower.contains("__viewstate") || lower.contains("asp.net_sessionid")) {
                backend = "ASP.NET"; language = coalesce(language, "C#");
                evidence.add("HTML: ASP.NET ViewState detectado");
            }
            if (lower.contains("thymeleaf") || lower.contains("th:text")) {
                framework = "Spring + Thymeleaf"; language = coalesce(language, "Java");
                evidence.add("HTML: Thymeleaf template detectado");
            }
            if (lower.contains("laravel") && framework == null) {
                framework = "Laravel"; language = coalesce(language, "PHP");
                evidence.add("HTML: Laravel signature");
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
                .detectedVersions(detectedVersions)
                .build();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

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

    /** Extrai a primeira versão semântica (x.y.z) de uma string. */
    private Optional<String> extractVersion(String value) {
        if (value == null) return Optional.empty();
        Matcher m = VERSION_PATTERN.matcher(value);
        return m.find() ? Optional.of(m.group(1)) : Optional.empty();
    }

    /** Extrai versão do WordPress de query strings como ?ver=6.4.3 */
    private Optional<String> extractWpVersion(String html) {
        Pattern p = Pattern.compile("\\?ver=(\\d+\\.\\d+(?:\\.\\d+)?)");
        Matcher m = p.matcher(html);
        return m.find() ? Optional.of(m.group(1)) : Optional.empty();
    }

    /** Extrai versão do Angular do atributo ng-version="x.y.z" */
    private Optional<String> extractNgVersion(String html) {
        Pattern p = Pattern.compile("ng-version=\"(\\d+\\.\\d+\\.\\d+)\"");
        Matcher m = p.matcher(html);
        return m.find() ? Optional.of(m.group(1)) : Optional.empty();
    }

    /** Extrai versão do jQuery de scripts como jquery-3.6.0.min.js ou jquery/3.6.0 */
    private Optional<String> extractJQueryVersion(String html) {
        Pattern p = Pattern.compile("jquery[/-](\\d+\\.\\d+\\.\\d+)");
        Matcher m = p.matcher(html.toLowerCase(Locale.ROOT));
        return m.find() ? Optional.of(m.group(1)) : Optional.empty();
    }

    private String coalesce(String existing, String fallback) {
        return existing != null ? existing : fallback;
    }
}