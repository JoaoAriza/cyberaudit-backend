package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.AppUser;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Quem é equipe da plataforma (e não apenas dono da própria conta).
 *
 * `Role.OWNER` NÃO serve para isso: `/auth/register` é público e cria todo mundo
 * já como OWNER da conta recém-criada. Usar o role como "staff" fazia com que
 * qualquer pessoa que se cadastrasse pulasse a exigência de posse de domínio no
 * scan ativo — anulando o controle inteiro.
 *
 * A lista vem de configuração (PLATFORM_STAFF_EMAILS, separado por vírgula) e
 * nasce VAZIA: por padrão ninguém tem privilégio cross-tenant. Preencha só com
 * os e-mails da sua equipe.
 */
@Service
public class PlatformStaffService {

    private final Set<String> staffEmails;

    public PlatformStaffService(@Value("${platform.staff-emails:}") String raw) {
        this.staffEmails = (raw == null || raw.isBlank())
                ? Set.of()
                : Arrays.stream(raw.split(","))
                        .map(String::trim)
                        .filter(s -> !s.isEmpty())
                        .map(s -> s.toLowerCase(Locale.ROOT))
                        .collect(Collectors.toUnmodifiableSet());
    }

    public boolean isStaff(AppUser user) {
        if (user == null || user.getEmail() == null) return false;
        return staffEmails.contains(user.getEmail().trim().toLowerCase(Locale.ROOT));
    }

    /** Quantos e-mails estão configurados — útil para log de boot / diagnóstico. */
    public int size() {
        return staffEmails.size();
    }
}
