package com.joao.cyberaudit.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Prova que o {@link SsrfPinningResolverProvider} está de fato plugado na JVM via
 * SPI (META-INF/services) e fecha o TOCTOU: uma vez pinado, {@code InetAddress}
 * devolve o endereço já auditado em vez de consultar o DNS de novo.
 *
 * Usa um host sob o TLD reservado .invalid (RFC 2606, nunca resolve de verdade):
 * se o pin não fosse honrado, o teste falharia com UnknownHostException — não há
 * como o assert passar "por acaso" com uma resposta real de DNS.
 */
class ScanDnsPinningTest {

    private static final String HOST = "pinned-host.invalid";
    private static final byte[] IP = {93, (byte) 184, (byte) 216, 34};

    @Test
    @DisplayName("host pinado devolve o endereco fixado, sem consultar o DNS")
    void hostPinadoDevolveEnderecoFixado() throws Exception {
        InetAddress fake = InetAddress.getByAddress(HOST, IP);
        ScanDnsPinRegistry.pin(HOST, List.of(fake));

        InetAddress[] resolvido = InetAddress.getAllByName(HOST);

        assertArrayEquals(IP, resolvido[0].getAddress(),
                "deveria devolver o endereço pinado, não uma resolução real (que falharia: .invalid nunca resolve)");
    }

    @Test
    @DisplayName("host sem pin nao pinado continua caindo no resolvedor padrao (nao intercepta tudo)")
    void hostNaoPinadoUsaResolverPadrao() {
        assertThrows(UnknownHostException.class,
                () -> InetAddress.getAllByName("nao-existe-e-nao-foi-pinado.invalid"));
    }

    @Test
    @DisplayName("SsrfGuard.validateHost pina os enderecos que validou")
    void validateHostPinaOsEnderecosValidados() throws Exception {
        SsrfGuard.validateHost("dns.google");

        List<InetAddress> pinado = ScanDnsPinRegistry.get("dns.google");

        assertNotNull(pinado, "validateHost deveria ter registrado um pin para o host validado");
    }
}
