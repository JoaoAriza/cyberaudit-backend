package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
@AllArgsConstructor
public class HttpFetchResult {
    private int statusCode;
    private String finalUrl;

    private Map<String, String> headers;

    private List<String> rawSetCookies;

    private String error;
}
