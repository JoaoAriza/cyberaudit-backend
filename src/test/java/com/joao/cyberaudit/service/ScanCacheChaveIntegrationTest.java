package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.Account;
import com.joao.cyberaudit.model.AccountType;
import com.joao.cyberaudit.model.AppUser;
import com.joao.cyberaudit.model.Plan;
import com.joao.cyberaudit.model.Role;
import com.joao.cyberaudit.model.ScanResult;
import com.joao.cyberaudit.repository.AccountRepository;
import com.joao.cyberaudit.repository.AppUserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * O cache de scan separa por endereço completo e por conta.
 *
 * Regressão do BUG-17 (cyberaudit-qa): a chave era host + modo + idioma. Por 2 minutos, a
 * busca do Juice Shop devolvia o scan ativo da home (sem as sondas no parâmetro, sem o
 * SQLi), e outra conta recebia o resultado sem o scan entrar no histórico dela. Decisões
 * do dono (2026-11-18): caminho e query na chave em todo modo; a conta também, com
 * visitantes dividindo uma entrada.
 *
 * Nenhum scan de verdade roda aqui. O primeiro passo de um scan é o {@code SSLService}, e
 * aqui ele é um mock que lança {@link ScanRodou}. Então "lançou ScanRodou" quer dizer "o
 * cache não acertou e o scan começou", e devolver um objeto quer dizer "acertou o cache".
 * Os hosts são {@code .invalid}: o SsrfGuard deixa passar quem não resolve, e nada sai
 * para a rede.
 */
@SpringBootTest
@ActiveProfiles("test")
class ScanCacheChaveIntegrationTest {

    /** Sinal de que o cache não acertou e o scan começou. */
    static class ScanRodou extends RuntimeException {
        ScanRodou() { super("o scan começou: o cache não acertou"); }
    }

    private static final String HOME  = "http://cache-teste.invalid:3000/";
    private static final String BUSCA = "http://cache-teste.invalid:3000/rest/products/search?q=apple";

    @MockitoBean    private SSLService sslService;
    @MockitoSpyBean private ScanCacheService cache;

    @Autowired private ScanOrchestrator orchestrator;
    @Autowired private AccountRepository accountRepository;
    @Autowired private AppUserRepository userRepository;

    @BeforeEach
    void scanFalhaNoPrimeiroPasso() {
        when(sslService.checkSSL(anyString())).thenThrow(new ScanRodou());
    }

    private Account novaConta() {
        return accountRepository.save(Account.builder()
                .type(AccountType.COMPANY)
                .plan(Plan.PRO)
                .displayName("Conta cache " + UUID.randomUUID())
                .createdAt(LocalDateTime.now())
                .build());
    }

    private AppUser novoUsuario(Account conta) {
        return userRepository.save(AppUser.builder()
                .name("Cliente cache")
                .email("cache-" + UUID.randomUUID() + "@example.com")
                .passwordHash("$2a$04$naoImportaParaEsteTeste000000000000000000000000000000")
                .role(Role.OWNER)
                .active(true)
                .createdAt(LocalDateTime.now())
                .account(conta)
                .build());
    }

    /** Roda um scan passivo que não acerta o cache e devolve a chave que ele consultou. */
    private String chaveUsada(String url, AppUser user) {
        clearInvocations(cache);
        assertThrows(ScanRodou.class, () -> orchestrator.execute(url, false, user, false));
        ArgumentCaptor<String> chave = ArgumentCaptor.forClass(String.class);
        verify(cache).get(chave.capture(), eq(ScanResult.class));
        return chave.getValue();
    }

    // ── O cenário do bug ────────────────────────────────────────────────────

    @Test
    @DisplayName("home guardada no cache: a mesma conta na home acerta; na busca e noutra conta, o scan roda")
    void acertoSoNoMesmoEnderecoENaMesmaConta() {
        AppUser cliente = novoUsuario(novaConta());
        ScanResult guardado = ScanResult.builder().url(HOME).build();
        String chave = chaveUsada(HOME, cliente);
        cache.put(chave, guardado);
        try {
            assertSame(guardado, orchestrator.execute(HOME, false, cliente, false),
                    "mesma conta, mesmo endereço: tem de acertar o cache");
            assertThrows(ScanRodou.class, () -> orchestrator.execute(BUSCA, false, cliente, false),
                    "a busca recebeu o resultado da home");
            assertThrows(ScanRodou.class,
                    () -> orchestrator.execute(HOME, false, novoUsuario(novaConta()), false),
                    "outra conta recebeu o resultado da primeira");
        } finally {
            // O cache é o mesmo para a classe toda: sem isto, o guardado vaza para os
            // outros testes.
            cache.invalidate(chave);
        }
    }

    // ── O que entra na chave ────────────────────────────────────────────────

    @Test
    @DisplayName("caminho entra na chave")
    void caminhoEntraNaChave() {
        AppUser cliente = novoUsuario(novaConta());
        assertNotEquals(chaveUsada(HOME, cliente), chaveUsada(BUSCA, cliente));
    }

    @Test
    @DisplayName("query entra na chave")
    void queryEntraNaChave() {
        AppUser cliente = novoUsuario(novaConta());
        assertNotEquals(chaveUsada(BUSCA, cliente),
                chaveUsada("http://cache-teste.invalid:3000/rest/products/search?q=banana", cliente));
    }

    @Test
    @DisplayName("porta entra na chave")
    void portaEntraNaChave() {
        AppUser cliente = novoUsuario(novaConta());
        assertNotEquals(chaveUsada(HOME, cliente),
                chaveUsada("http://cache-teste.invalid:8080/", cliente));
    }

    @Test
    @DisplayName("conta entra na chave, e visitante não divide com conta")
    void contaEntraNaChave() {
        String daPrimeira = chaveUsada(HOME, novoUsuario(novaConta()));
        assertNotEquals(daPrimeira, chaveUsada(HOME, novoUsuario(novaConta())));
        assertNotEquals(daPrimeira, chaveUsada(HOME, null));
    }

    // ── Controles: o que continua dividindo ─────────────────────────────────

    @Test
    @DisplayName("mesmo endereço escrito de outro jeito (sem barra, com #) dá a mesma chave")
    void mesmoEnderecoMesmaChave() {
        AppUser cliente = novoUsuario(novaConta());
        String chave = chaveUsada(HOME, cliente);
        assertEquals(chave, chaveUsada("http://cache-teste.invalid:3000", cliente));
        assertEquals(chave, chaveUsada("http://cache-teste.invalid:3000/#topo", cliente));
    }

    @Test
    @DisplayName("membros da mesma conta dividem a entrada; visitantes também")
    void mesmaContaEVisitantesDividem() {
        Account conta = novaConta();
        assertEquals(chaveUsada(HOME, novoUsuario(conta)), chaveUsada(HOME, novoUsuario(conta)));
        assertEquals(chaveUsada(HOME, null), chaveUsada(HOME, null));
    }
}
