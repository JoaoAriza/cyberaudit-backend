package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class DirectoryListingFinding {
    private String path;
    private int statusCode;
    private boolean listingEnabled;
    private String evidence;
    private String severity;
}