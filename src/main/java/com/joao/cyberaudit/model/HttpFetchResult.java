package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;
import java.util.Map;

@Getter @Setter @AllArgsConstructor @NoArgsConstructor
public class HttpFetchResult {
    private int statusCode;
    private String finalUrl;
    private Map<String, String> headers;
    private List<String> rawSetCookies;
    private String error;
}
