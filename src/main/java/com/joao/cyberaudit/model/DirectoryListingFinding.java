package com.joao.cyberaudit.model;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class DirectoryListingFinding {
    private String path;
    private int statusCode;
    private boolean listingEnabled;
    private String evidence;
    private String severity;
}