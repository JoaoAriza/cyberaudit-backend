package com.joao.cyberaudit.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.SocketTimeoutException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DomainProtectionServiceTest {

    private static final String SECRET = "segredo-de-teste-com-mais-de-32-caracteres!!";

    private final DomainProtectionService service = new DomainProtectionService(SECRET);

    @Test
    @DisplayName("token é determinístico para o mesmo host")
    void tokenDeterministico() {
        assertEquals(service.generateVerificationToken("example.com"),
                service.generateVerificationToken("example.com"));
    }

    @Test
    @DisplayName("token normaliza caixa e ponto final do FQDN")
    void tokenNormalizaHost() {
        String base = service.generateVerificationToken("example.com");
        assertEquals(base, service.generateVerificationToken("EXAMPLE.COM"));
        assertEquals(base, service.generateVerificationToken("example.com."));
        assertEquals(base, service.generateVerificationToken("  example.com  "));
    }

    @Test
    @DisplayName("hosts diferentes geram tokens diferentes")
    void tokenPorHost() {
        assertNotEquals(service.generateVerificationToken("example.com"),
                service.generateVerificationToken("outro.com"));
        // subdomínio não herda o token do domínio raiz
        assertNotEquals(service.generateVerificationToken("example.com"),
                service.generateVerificationToken("app.example.com"));
    }

    @Test
    @DisplayName("token depende do segredo do servidor — não é derivável só do host")
    void tokenDependeDoSegredo() {
        DomainProtectionService outro = new DomainProtectionService("outro-segredo-de-servidor-aqui!!");
        assertNotEquals(service.generateVerificationToken("example.com"),
                outro.generateVerificationToken("example.com"));
    }

    @Test
    @DisplayName("token tem o prefixo esperado e 32 hex")
    void formatoDoToken() {
        String token = service.generateVerificationToken("example.com");
        assertTrue(token.startsWith("cyberaudit-verify="), token);
        String value = token.substring("cyberaudit-verify=".length());
        assertEquals(32, value.length());
        assertTrue(value.matches("[0-9a-f]{32}"), value);
    }

    @Test
    @DisplayName("verificação recusa host interno sem fazer requisição")
    void recusaHostInterno() {
        assertFalse(service.isOwnershipVerified("127.0.0.1"));
        assertFalse(service.isOwnershipVerified("169.254.169.254"));
        assertFalse(service.isOwnershipVerified("localhost"));
        assertFalse(service.isOwnershipVerified("192.168.1.1"));
    }

    /**
     * Regressão do BUG-05 (cyberaudit-qa). O {@code /scan/verify-check} é público e o
     * guard validava o texto cru do host: com porta, espaço ou um delimitador de URL,
     * o {@code InetAddress} não resolvia e o guard deixava passar — mas o {@code URI}
     * montado depois extraía {@code 127.0.0.1} e a requisição saía.
     *
     * Só afirmar {@code false} não prova nada: contra um destino interno a verificação
     * falha de qualquer jeito (o TLS não fecha). O que se afirma é que NENHUMA conexão
     * chegou ao socket que faz o papel de serviço interno.
     */
    @ParameterizedTest
    @ValueSource(strings = {
            "127.0.0.1:%d",
            "127.0.0.1:%d/",
            "127.0.0.1:%d#",
            " 127.0.0.1:%d",
            "x@127.0.0.1:%d"
    })
    @DisplayName("host disfarçado (porta, espaço, delimitador de URL) não gera conexão a destino interno")
    void naoConectaEmDestinoInternoDisfarcado(String formato) throws Exception {
        try (ServerSocket servicoInterno = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))) {
            servicoInterno.setSoTimeout(300);
            String host = formato.formatted(servicoInterno.getLocalPort());

            assertFalse(service.isOwnershipVerified(host));

            // Uma conexão feita teria completado o handshake TCP e estaria na fila do
            // accept — mesmo que o cliente já tenha desistido no TLS.
            assertThrows(SocketTimeoutException.class, servicoInterno::accept,
                    "o serviço conectou em '" + host + "'");
        }
    }

    @Test
    @DisplayName("verificação recusa host nulo ou vazio")
    void recusaHostVazio() {
        assertFalse(service.isOwnershipVerified(null));
        assertFalse(service.isOwnershipVerified(""));
        assertFalse(service.isOwnershipVerified("   "));
    }
}
