package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.Map;

@Data
@AllArgsConstructor
public class HttpFetchResult {
    private int statusCode;
    private String finalUrl;
    private Map<String, String> headers;
    private String error;
}
