package com.joao.cyberaudit.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.joao.cyberaudit.model.SubdomainTakeoverFinding;
import org.springframework.stereotype.Service;
import org.xbill.DNS.*;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

@Service
public class SubdomainTakeoverService {

    private record TakeoverFingerprint(
            String cnameSuffix, String bodyFingerprint, String serviceName, String severity) {}

    private static final List<TakeoverFingerprint> FINGERPRINTS = List.of(
            new TakeoverFingerprint("github.io",          "There isn't a GitHub Pages site here",          "GitHub Pages",    "CRITICAL"),
            new TakeoverFingerprint("github.io",          "For root URLs (like http://github.com/)",        "GitHub Pages",    "CRITICAL"),
            new TakeoverFingerprint("azurewebsites.net",  "404 Web Site not found",                        "Azure App",       "HIGH"),
            new TakeoverFingerprint("cloudapp.net",       "404 - This page can",                           "Azure Cloud",     "HIGH"),
            new TakeoverFingerprint("cloudapp.azure.com", "404",                                           "Azure Cloud",     "HIGH"),
            new TakeoverFingerprint("s3.amazonaws.com",   "NoSuchBucket",                                  "AWS S3",          "CRITICAL"),
            new TakeoverFingerprint("s3-website",         "NoSuchBucket",                                  "AWS S3 Website",  "CRITICAL"),
            new TakeoverFingerprint("storage.googleapis", "NoSuchBucket",                                  "GCS Bucket",      "CRITICAL"),
            new TakeoverFingerprint("herokuapp.com",      "No such app",                                   "Heroku",          "CRITICAL"),
            new TakeoverFingerprint("netlify.app",        "Not Found - Request ID:",                       "Netlify",         "HIGH"),
            new TakeoverFingerprint("netlify.com",        "Not Found - Request ID:",                       "Netlify",         "HIGH"),
            new TakeoverFingerprint("vercel.app",         "404: NOT_FOUND",                                "Vercel",          "HIGH"),
            new TakeoverFingerprint("myshopify.com",      "Sorry, this shop is currently unavailable",     "Shopify",         "HIGH"),
            new TakeoverFingerprint("ghost.io",           "The thing you were looking for is no longer",   "Ghost",           "HIGH"),
            new TakeoverFingerprint("surge.sh",           "project not found",                             "Surge.sh",        "CRITICAL"),
            new TakeoverFingerprint("bitbucket.io",       "Repository not found",                          "Bitbucket Pages", "CRITICAL"),
            new TakeoverFingerprint("tumblr.com",         "There's nothing here.",                         "Tumblr",          "MEDIUM"),
            new TakeoverFingerprint("zendesk.com",        "Help Center Closed",                            "Zendesk",         "HIGH"),
            new TakeoverFingerprint("readthedocs.io",     "unknown domain",                                "ReadTheDocs",     "HIGH"),
            new TakeoverFingerprint("readthedocs.org",    "unknown domain",                                "ReadTheDocs",     "HIGH"),
            new TakeoverFingerprint("pantheonsite.io",    "The gods are wise",                             "Pantheon",        "HIGH"),
            new TakeoverFingerprint("freshdesk.com",      "There is no helpdesk here",                     "Freshdesk",       "HIGH"),
            new TakeoverFingerprint("campaignmonitor.com","Double check the URL",                          "Campaign Monitor","MEDIUM"),
            new TakeoverFingerprint("launchrock.com",     "It looks like you may have taken a wrong turn", "Launchrock",      "HIGH"),
            new TakeoverFingerprint("unbounce.com",       "The requested URL was not found",               "Unbounce",        "HIGH"),
            new TakeoverFingerprint("helpjuice.com",      "We could not find what",                        "HelpJuice",       "HIGH"),
            new TakeoverFingerprint("teamwork.com",       "Oops - We didn't find your site",               "Teamwork",        "HIGH"),
            new TakeoverFingerprint("webflow.io",         "The page you are looking for doesn't exist",    "Webflow",         "HIGH"),
            new TakeoverFingerprint("strikingly.com",     "page not found",                                "Strikingly",      "MEDIUM"),
            new TakeoverFingerprint("wordpress.com",      "Do you want to register",                       "WordPress.com",   "MEDIUM"),
            new TakeoverFingerprint("tilda.ws",           "Please renew your subscription",                "Tilda",           "MEDIUM"),
            new TakeoverFingerprint("desk.com",           "Please try again or try Desk.com free",         "Desk.com",        "HIGH"),
            new TakeoverFingerprint("fastly.net",         "Fastly error: unknown domain",                  "Fastly",          "HIGH"),
            new TakeoverFingerprint("cargo.site",         "If you're moving your domain",                  "Cargo",           "MEDIUM")
    );

    private static final List<String> WORDLIST = List.of(
            "www", "api", "dev", "staging", "test", "beta", "app", "mail",
            "docs", "help", "support", "admin", "blog", "shop", "store",
            "cdn", "assets", "static", "media", "old", "legacy", "v2",
            "portal", "dashboard", "status", "demo", "sandbox", "preview",
            "secure", "auth", "login", "ftp", "smtp", "images", "files"
    );

    private static final int MAX_SUBDOMAINS    = 50;
    private static final int CONCURRENT_PROBES = 10;

    private final CrtShService crtShService; // ← compartilhado
    private final MessageCatalog catalog;
    private final HttpClient   httpClient = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)  // redirects seguidos por ScannerHttp.sendFollowingSafely (revalida cada hop)
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    public SubdomainTakeoverService(CrtShService crtShService, MessageCatalog catalog) {
        this.crtShService = crtShService;
        this.catalog = catalog;
    }

    public List<SubdomainTakeoverFinding> scan(String targetUrl) {
        String host = extractHost(targetUrl);
        if (host == null) return List.of();

        // Usa CrtShService compartilhado — não faz nova requisição se CT já buscou
        Set<String> subdomains = new LinkedHashSet<>();
        for (JsonNode cert : crtShService.fetchCerts(host)) {
            String nameValue = cert.path("name_value").asText("");
            for (String name : nameValue.split("[\\n,]")) {
                name = name.trim().toLowerCase();
                if (!name.startsWith("*") && name.endsWith("." + host) && !name.equals(host)) {
                    subdomains.add(name);
                    if (subdomains.size() >= 30) break;
                }
            }
            if (subdomains.size() >= 30) break;
        }
        for (String word : WORDLIST) subdomains.add(word + "." + host);

        List<String> toProbe = subdomains.stream()
                .filter(s -> !s.equals(host))
                .distinct()
                .limit(MAX_SUBDOMAINS)
                .collect(Collectors.toList());

        if (toProbe.isEmpty()) return List.of();

        ExecutorService pool = Executors.newFixedThreadPool(CONCURRENT_PROBES);
        List<CompletableFuture<SubdomainTakeoverFinding>> futures = toProbe.stream()
                .map(sub -> CompletableFuture
                        .supplyAsync(() -> probe(sub), pool)
                        .exceptionally(e -> null))
                .collect(Collectors.toList());

        try {
            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                    .get(60, TimeUnit.SECONDS);
        } catch (Exception ignored) {}

        pool.shutdownNow();

        return futures.stream()
                .map(f -> f.getNow(null))
                .filter(Objects::nonNull)
                .sorted(Comparator.comparingInt(f -> severityOrder(f.getSeverity())))
                .collect(Collectors.toList());
    }

    private SubdomainTakeoverFinding probe(String subdomain) {
        String cnameTarget = resolveCname(subdomain);
        if (cnameTarget == null) return null;

        TakeoverFingerprint matched = FINGERPRINTS.stream()
                .filter(fp -> cnameTarget.contains(fp.cnameSuffix()))
                .findFirst().orElse(null);
        if (matched == null) return null;

        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create("https://" + subdomain))
                    .GET().timeout(Duration.ofSeconds(6))
                    .header("User-Agent", ScannerHttp.USER_AGENT).build();

            HttpResponse<String> resp = ScannerHttp.sendFollowingSafely(httpClient, req, ScannerHttp.limitedString());
            String body = resp.body() != null ? resp.body() : "";

            if (body.toLowerCase().contains(matched.bodyFingerprint().toLowerCase())) {
                return SubdomainTakeoverFinding.builder()
                        .subdomain(subdomain).cnameTarget(cnameTarget)
                        .service(matched.serviceName())
                        .vulnerability(catalog.desc("TAKEOVER_UNCLAIMED", matched.serviceName()))
                        .evidence(extractSnippet(body, matched.bodyFingerprint()))
                        .severity(matched.severity()).status("VULNERABLE").build();
            }
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : "";
            if (msg.contains("Connection refused") || msg.contains("timed out")) {
                return SubdomainTakeoverFinding.builder()
                        .subdomain(subdomain).cnameTarget(cnameTarget)
                        .service(matched.serviceName())
                        .vulnerability(catalog.desc("TAKEOVER_NO_RESPONSE", matched.serviceName()))
                        .evidence(catalog.evidence("TAKEOVER_REFUSED", cnameTarget))
                        .severity("MEDIUM").status("POTENTIAL").build();
            }
        }
        return null;
    }

    private String resolveCname(String hostname) {
        try {
            Lookup lookup = new Lookup(hostname, Type.CNAME);
            lookup.run();
            if (lookup.getResult() == Lookup.SUCCESSFUL && lookup.getAnswers() != null) {
                for (org.xbill.DNS.Record record : lookup.getAnswers()) {
                    if (record instanceof CNAMERecord cname)
                        return cname.getTarget().toString().toLowerCase();
                }
            }
            return null;
        } catch (Exception e) { return null; }
    }

    private String extractSnippet(String body, String fingerprint) {
        int idx = body.toLowerCase().indexOf(fingerprint.toLowerCase());
        if (idx < 0) return fingerprint;
        int start = Math.max(0, idx - 30);
        int end   = Math.min(body.length(), idx + fingerprint.length() + 30);
        return "..." + body.substring(start, end).replaceAll("[\\r\\n\\t]+", " ").trim() + "...";
    }

    private String extractHost(String url) {
        try { return URI.create(url).getHost(); }
        catch (Exception e) { return null; }
    }

    private int severityOrder(String sev) {
        return switch (sev != null ? sev.toUpperCase() : "") {
            case "CRITICAL" -> 0; case "HIGH" -> 1; case "MEDIUM" -> 2; default -> 3;
        };
    }
}