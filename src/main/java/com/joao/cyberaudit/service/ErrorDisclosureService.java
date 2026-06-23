package com.joao.cyberaudit.service;

import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

@Service
public class ErrorDisclosureService {

    private final HttpClient client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.ALWAYS)
            .connectTimeout(Duration.ofSeconds(8))
            .build();

    // PASSIVO: só diz se há parâmetros (superfície de entrada)
    public boolean hasQueryParams(String url) {
        return url != null && url.contains("?") && url.indexOf('?') < url.length() - 1;
    }

    // ATIVO (opt-in): faz 1 request extra e busca padrões de erro de banco/SQL na resposta
    public boolean detectsDbErrorLeakage(String urlWithParams) {
        try {
            if (!hasQueryParams(urlWithParams)) return false;

            String mutated = mutateFirstParamValue(urlWithParams);

            HttpRequest req = HttpRequest.newBuilder(URI.create(mutated))
                    .GET()
                    .timeout(Duration.ofSeconds(12))
                    .header("User-Agent", ScannerHttp.USER_AGENT)
                    .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,/;q=0.8")
                    .build();

            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
            String body = resp.body() == null ? "" : resp.body().toLowerCase();

            return containsDbErrorPatterns(body);

        } catch (Exception e) {
            return false;
        }
    }

    private String mutateFirstParamValue(String url) {
        int q = url.indexOf('?');
        String base = url.substring(0, q);
        String query = url.substring(q + 1);

        String[] parts = query.split("&", 2);
        String first = parts[0];
        String rest = (parts.length > 1) ? "&" + parts[1] : "";

        String[] kv = first.split("=", 2);
        String key = kv[0];
        String value = kv.length > 1 ? kv[1] : "";


        String decoded = URLDecoder.decode(value, StandardCharsets.UTF_8);
        String newValue = decoded + "'";
        String encoded = URLEncoder.encode(newValue, StandardCharsets.UTF_8);

        return base + "?" + key + "=" + encoded + rest;
    }

    private boolean containsDbErrorPatterns(String body) {
        List<String> patterns = List.of(
                "you have an error in your sql syntax",
                "unclosed quotation mark after the character string",
                "syntax error at or near",
                "sqlstate[",
                "jdbc exception",
                "java.sql.sqlexception",
                "mysqli_fetch",
                "pg_query()",
                "sqlite3.operationalerror",
                "ora-00907",
                "ora-00933",
                "ora-00942",
                "odbc driver",
                "warning: mysql_",
                "supplied argument is not a valid mysql"
        );

        for (String p : patterns) {
            if (body.contains(p)) return true;
        }
        return false;
    }
}