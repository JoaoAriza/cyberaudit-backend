package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.Role;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PlatformStaffServiceTest {

    private static AppUser user(String email, Role role) {
        return AppUser.builder().email(email).role(role).build();
    }

    @Test
    @DisplayName("configuração vazia: ninguém é staff — nem OWNER")
    void vazioNaoTemStaff() {
        PlatformStaffService service = new PlatformStaffService("");

        assertEquals(0, service.size());
        assertFalse(service.isStaff(user("qualquer@um.com", Role.OWNER)));
        assertFalse(service.isStaff(user("admin@um.com", Role.ADMIN)));
        assertFalse(service.isStaff(null));
    }

    @Test
    @DisplayName("null na configuração é tratado como vazio")
    void nullNaoQuebra() {
        assertEquals(0, new PlatformStaffService(null).size());
        assertEquals(0, new PlatformStaffService("   ").size());
    }

    @Test
    @DisplayName("reconhece apenas os e-mails listados, ignorando caixa e espaços")
    void reconheceListados() {
        PlatformStaffService service =
                new PlatformStaffService(" Equipe@cyberaudit.io , suporte@cyberaudit.io ");

        assertEquals(2, service.size());
        assertTrue(service.isStaff(user("equipe@cyberaudit.io", Role.FREE_EMPLOYEE)));
        assertTrue(service.isStaff(user("EQUIPE@CYBERAUDIT.IO", Role.FREE_EMPLOYEE)));
        assertTrue(service.isStaff(user("  suporte@cyberaudit.io  ", Role.FREE_EMPLOYEE)));
    }

    @Test
    @DisplayName("role OWNER não concede staff — /auth/register entrega OWNER a qualquer um")
    void ownerNaoEStaff() {
        PlatformStaffService service = new PlatformStaffService("equipe@cyberaudit.io");

        assertFalse(service.isStaff(user("atacante@gmail.com", Role.OWNER)));
        assertFalse(service.isStaff(user(null, Role.OWNER)));
    }

    @Test
    @DisplayName("entradas vazias entre vírgulas são descartadas")
    void ignoraEntradasVazias() {
        PlatformStaffService service = new PlatformStaffService("a@b.com,,  ,c@d.com,");

        assertEquals(2, service.size());
        assertFalse(service.isStaff(user("", Role.OWNER)));
    }
}
