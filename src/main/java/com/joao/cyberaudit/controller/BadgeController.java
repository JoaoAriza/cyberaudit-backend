package com.joao.cyberaudit.controller;

import com.joao.cyberaudit.service.BadgeService;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/badge")
public class BadgeController {

    private final BadgeService badgeService;

    public BadgeController(BadgeService badgeService) {
        this.badgeService = badgeService;
    }

    @GetMapping(value = "/{host}", produces = "image/svg+xml")
    public ResponseEntity<String> badge(
            @PathVariable String host,
            @RequestParam(defaultValue = "classic") String style) {

        String svg = badgeService.generateBadge(host, style);

        return ResponseEntity.ok()
                .contentType(MediaType.valueOf("image/svg+xml"))
                .cacheControl(CacheControl.maxAge(5, TimeUnit.MINUTES))
                .header("Cache-Control", "no-cache, max-age=300")
                .header("Content-Disposition", "inline")
                .body(svg);
    }
}