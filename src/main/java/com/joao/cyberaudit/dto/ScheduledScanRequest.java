package com.joao.cyberaudit.dto;

import lombok.Data;

@Data
public class ScheduledScanRequest {
    private String  host;
    private boolean active;
    private String  frequency;   // "DAILY" | "WEEKLY"
    private String  path;        // caminho dentro do dominio (ex: "/login"); vazio = raiz
    private int     preferredHour; // 0-23, no fuso da conta de quem cria (ver UserTimeZoneService)
    private boolean notifyEmail;
}
