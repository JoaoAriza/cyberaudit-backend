package com.joao.cyberaudit.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.time.LocalDate;
import java.time.LocalDateTime;

@Entity
@Table(name = "guest_daily_scans")
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor
public class GuestScanLimit {

    @EmbeddedId
    private GuestScanLimitId id;

    private int count;
    private LocalDateTime lastScanAt;

    @Embeddable
    @Getter @Setter
@NoArgsConstructor @AllArgsConstructor
    public static class GuestScanLimitId implements Serializable {
        private String ip;
        private LocalDate scanDate;
    }
}