package com.joao.cyberaudit.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.time.LocalDate;
import java.time.LocalDateTime;

@Entity
@Table(name = "guest_daily_scans")
@Data @NoArgsConstructor @AllArgsConstructor
public class GuestScanLimit {

    @EmbeddedId
    private GuestScanLimitId id;

    private int count;
    private LocalDateTime lastScanAt;

    @Embeddable
    @Data @NoArgsConstructor @AllArgsConstructor
    public static class GuestScanLimitId implements Serializable {
        private String ip;
        private LocalDate scanDate;
    }
}