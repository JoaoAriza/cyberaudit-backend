package com.joao.cyberaudit.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "app_users")
@Getter @Setter @Builder @NoArgsConstructor @AllArgsConstructor
public class AppUser implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false)
    private String name;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(nullable = false)
    private String passwordHash;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role;

    private String jobTitle;
    private String country;

    /**
     * Fuso do usuário, no identificador IANA ({@code America/Sao_Paulo}) — nunca
     * um offset como "-03:00". O offset é um fato sobre um INSTANTE, não sobre um
     * lugar: guardado, erra na próxima virada de horário de verão. O identificador
     * carrega as regras e o {@code ZoneId} aplica a da data certa.
     *
     * Vale para o que o servidor gera sem navegador na frente — hora do
     * agendamento, carimbo do PDF, corte de dia nos filtros. O que é renderizado
     * na tela não passa por aqui: ali o próprio navegador converte o instante UTC
     * que a API manda, e acompanha quem viaja.
     *
     * Nulo em quem nunca abriu a interface depois desta coluna existir — cai em
     * UTC, que é o que essas pessoas já recebiam.
     */
    @Column(length = 64)
    private String timezone;

    /**
     * Marca a escolha feita no perfil, para a detecção automática do navegador não
     * atropelá-la no próximo login. Sem isto, quem administra do exterior o servidor
     * de casa não conseguiria manter o relatório no fuso da operação.
     */
    // DEFAULT explicito: com ddl-auto=update esta coluna NOT NULL entra numa tabela
    // que ja tem linhas, e sem default o Postgres recusa o ALTER. Mesmo motivo do
    // columnDefinition em ScanRecord.origin.
    @Builder.Default
    @Column(nullable = false, columnDefinition = "BOOLEAN DEFAULT FALSE")
    private boolean timezoneManual = false;

    @Column(nullable = false)
    private boolean active;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "account_id")
    private Account account;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "invited_by")
    private AppUser invitedBy;

    @Builder.Default
    @Column(nullable = false)
    private boolean termsAccepted = false;

    private LocalDateTime termsAcceptedAt;

    /**
     * Quando a senha foi trocada pela última vez. Null = nunca foi trocada.
     *
     * O filtro JWT compara este carimbo com o {@code iat} do token e recusa o que
     * foi emitido antes. É o que faz a redefinição de senha derrubar as sessões
     * abertas — JWT é stateless e não tem como ser revogado por conta própria, então
     * sem o carimbo o token anterior continuaria valendo até expirar (24h), e quem
     * tomou a conta seguiria dentro dela depois de o dono trocar a senha.
     *
     * Nulo é permitido de propósito: as contas que já existem sobem sem carimbo, e
     * inventar um valor no deploy deslogaria todo mundo de uma vez.
     */
    private LocalDateTime passwordChangedAt;

    private String totpSecret;

    @Builder.Default
    @Column(nullable = false)
    private boolean totpEnabled = false;

    @Builder.Default
    @Column(nullable = false)
    private boolean emailOtpEnabled = false;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_" + role.name()));
    }

    @Override public String getPassword()    { return passwordHash; }
    @Override public String getUsername()    { return email; }
    @Override public boolean isAccountNonExpired()    { return true; }
    @Override public boolean isAccountNonLocked()     { return active; }
    @Override public boolean isCredentialsNonExpired(){ return true; }
    @Override public boolean isEnabled()              { return active; }
}
