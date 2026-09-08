package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.repository.AppUserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

/**
 * Fuso do usuário — a fonte para o que o servidor gera sem navegador na frente.
 *
 * O sistema grava e trafega tudo em UTC, e a tela converte sozinha para o fuso de
 * quem está olhando. Sobram os pontos em que não existe navegador no momento da
 * renderização: a hora em que um agendamento deve disparar, o carimbo do PDF, o
 * corte de dia de um filtro por período. É só para esses que este fuso existe.
 *
 * A fonte é o próprio navegador ({@code Intl.DateTimeFormat().resolvedOptions().timeZone}),
 * que devolve o identificador IANA configurado no sistema operacional — a mesma
 * informação do relógio do canto da tela. Não é derivado do IP: VPN, proxy
 * corporativo e CGNAT de operadora erram justamente no público desta ferramenta,
 * país não determina fuso (o Brasil tem quatro) e geolocalizar quem usa o produto
 * seria criar perfil de localização num sistema que audita LGPD.
 */
@Service
public class UserTimeZoneService {

    /** Quem nunca informou fuso continua recebendo o que já recebia. */
    public static final ZoneId PADRAO = ZoneId.of("UTC");

    /** Locale fixo: os relatórios exportáveis são monolíngues em inglês. */
    private static final DateTimeFormatter CARIMBO =
            DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm z", Locale.ENGLISH);

    private final AppUserRepository userRepository;

    public UserTimeZoneService(AppUserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Fuso efetivo do usuário. Nunca lança: um identificador que deixou de existir
     * na base de fusos do JDK não pode derrubar a geração de um relatório.
     */
    public ZoneId zonaDe(AppUser user) {
        if (user == null || user.getTimezone() == null || user.getTimezone().isBlank()) return PADRAO;
        try {
            return ZoneId.of(user.getTimezone());
        } catch (Exception e) {
            return PADRAO;
        }
    }

    /**
     * @param manual true quando veio do seletor do perfil — nesse caso passa a
     *               valer sobre a detecção automática dos próximos logins.
     */
    @Transactional
    public AppUser definir(AppUser user, String zonaBruta, boolean manual) {
        String zona = validar(zonaBruta);

        // Detecção automática não desfaz escolha explícita: quem fixou o fuso no
        // perfil continua com ele mesmo abrindo a interface de outro país.
        if (!manual && user.isTimezoneManual()) return user;

        user.setTimezone(zona);
        user.setTimezoneManual(manual);
        return userRepository.save(user);
    }

    /** Volta para o fuso detectado pelo navegador no próximo acesso. */
    @Transactional
    public AppUser automatico(AppUser user) {
        user.setTimezone(null);
        user.setTimezoneManual(false);
        return userRepository.save(user);
    }

    /**
     * Aceita só identificador IANA conhecido do JDK.
     *
     * Offset ("-03:00", "GMT-3") é recusado de propósito, ainda que o ZoneId.of
     * aceite: offset descreve um instante, não um lugar, e congelaria o usuário
     * fora do horário de verão dele. O ZoneId.of também aceita ids que não estão
     * na base IANA, por isso a conferência é contra getAvailableZoneIds().
     */
    private String validar(String bruto) {
        if (bruto == null || bruto.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Fuso horário é obrigatório.");
        }
        String zona = bruto.trim();
        if (zona.length() > 64 || !ZoneId.getAvailableZoneIds().contains(zona)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Fuso horário inválido: use um identificador IANA, como America/Sao_Paulo.");
        }
        return zona;
    }

    /**
     * Carimbo "gerado em" dos documentos que o servidor produz.
     *
     * Leva o fuso escrito no texto porque um PDF sai da tela que sabia converter:
     * quem abrir o arquivo daqui a um mês não tem como perguntar ao navegador em
     * que fuso aquilo foi gerado.
     */
    public static String carimbo(ZoneId zona) {
        return ZonedDateTime.now(zona).format(CARIMBO);
    }

    // ── Corte de dia ─────────────────────────────────────────────────────────

    /**
     * Início do dia civil do usuário, convertido para UTC.
     *
     * Um filtro "de 08/09 a 08/09" quer dizer o dia de QUEM FILTRA. Cortando pelo
     * dia UTC, um scan das 22h em São Paulo cai no dia seguinte do relatório e
     * some da busca de quem o executou.
     */
    public static LocalDateTime inicioDoDia(LocalDate dia, ZoneId zona) {
        return emUtc(dia.atStartOfDay(zona));
    }

    /** Último instante do dia civil do usuário, em UTC — limite superior inclusivo. */
    public static LocalDateTime fimDoDia(LocalDate dia, ZoneId zona) {
        return emUtc(dia.plusDays(1).atStartOfDay(zona)).minusSeconds(1);
    }

    private static LocalDateTime emUtc(ZonedDateTime momento) {
        return momento.withZoneSameInstant(ZoneOffset.UTC).toLocalDateTime();
    }
}
