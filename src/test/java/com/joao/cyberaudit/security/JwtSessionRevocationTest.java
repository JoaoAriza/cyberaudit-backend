package com.joao.cyberaudit.security;

import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.Role;
import com.joao.cyberaudit.repository.AppUserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Revogação de sessão por troca de senha, com a cadeia de filtros subida.
 *
 * O que se quer provar: um JWT emitido ANTES da troca de senha para de autenticar.
 * Antes disto, redefinir a senha não expulsava ninguém — o token anterior valia até
 * expirar (24h), então quem tivesse tomado a conta continuava dentro dela enquanto o
 * dono achava que tinha resolvido o problema trocando a senha.
 *
 * <h2>Por que as afirmações são sobre 401 × 403</h2>
 *
 * O alvo é {@code GET /history/recent}, que é {@code .authenticated()}. Para um
 * usuário SEM conta associada o controller responde 403 de propósito. Então:
 *
 * <ul>
 *   <li><b>401</b> = o filtro não autenticou — é o que a revogação tem de produzir,
 *       e é o status que o Frontend usa para derrubar a sessão e mandar para o login;</li>
 *   <li><b>403</b> = o filtro autenticou e quem recusou foi o controller — prova que
 *       o token continua valendo.</li>
 * </ul>
 *
 * A distinção é justamente o que separa "token revogado" de "token bom". Como no
 * {@code SecurityChainIntegrationTest}, o teste afirma sobre STATUS, nunca sobre corpo:
 * o que está sob teste é quem responde primeiro.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class JwtSessionRevocationTest {

    @Autowired private MockMvc mvc;
    @Autowired private JwtUtil jwtUtil;
    @Autowired private AppUserRepository userRepository;

    /** Usuário novo, sem conta: o controller responde 403 quando o filtro autentica. */
    private AppUser novoUsuario(LocalDateTime senhaTrocadaEm) {
        return userRepository.save(AppUser.builder()
                .name("Cliente Teste")
                .email("revogacao-" + UUID.randomUUID() + "@example.com")
                .passwordHash("$2a$04$naoImportaParaEsteTeste000000000000000000000000000000")
                .role(Role.OWNER)
                .active(true)
                .createdAt(LocalDateTime.now())
                .passwordChangedAt(senhaTrocadaEm)
                .build());
    }

    private void chamarHistorico(String token, int statusEsperado) throws Exception {
        mvc.perform(get("/history/recent").header("Authorization", "Bearer " + token))
                .andExpect(status().is(statusEsperado));
    }

    // ── A regressão ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("token emitido antes da troca de senha deixa de autenticar — 401")
    void tokenAnteriorATrocaDeSenhaNaoAutentica() throws Exception {
        AppUser user = novoUsuario(null);
        String token = jwtUtil.generateToken(user);

        // Sessão vale enquanto não há troca registrada.
        chamarHistorico(token, 403);

        // A troca acontece DEPOIS de o token ter sido emitido.
        user.setPasswordChangedAt(LocalDateTime.now().plusMinutes(1));
        userRepository.save(user);

        chamarHistorico(token, 401);
    }

    @Test
    @DisplayName("token emitido depois da troca continua valendo — não derruba quem acabou de entrar")
    void tokenPosteriorATrocaContinuaValendo() throws Exception {
        // Quem redefine a senha e entra de novo tem de conseguir usar a conta. Se a
        // conferência fosse por igualdade em vez de "anterior a", este login novo
        // seria derrubado junto com o antigo.
        AppUser user = novoUsuario(LocalDateTime.now().minusMinutes(5));

        chamarHistorico(jwtUtil.generateToken(user), 403);
    }

    @Test
    @DisplayName("conta sem carimbo não é afetada — as que já existiam não são deslogadas no deploy")
    void contaSemCarimboNaoERevogada() throws Exception {
        // `passwordChangedAt` sobe nulo para todas as linhas que já estão no banco.
        // Se nulo revogasse, o deploy desta mudança deslogaria a base inteira.
        AppUser user = novoUsuario(null);

        chamarHistorico(jwtUtil.generateToken(user), 403);
    }
}
