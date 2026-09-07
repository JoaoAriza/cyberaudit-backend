package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.TlsDetails;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.support.ResourceBundleMessageSource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Protocolo deprecado OFERECIDO ao lado do negociado deve acender.
 *
 * O ponto cego que motivou: o inspetor abria um socket, deixava negociar o
 * melhor protocolo (1.3) e reportava a partir dele. Um alvo atrás de Cloudflare
 * (mínimo TLS 1.0 por padrão) aceita 1.0/1.1, mas a negociação fecha em 1.3, e o
 * módulo dava SECURE. Testado ao vivo em www.cyberauditapp.com contra o testssl:
 * o site oferecia TLS 1.0 e 1.1 e o scanner não via.
 *
 * evaluate() é a decisão pura, separada da sondagem de rede, e é o que estes
 * testes fixam.
 */
class TlsDeprecatedProtocolTest {

    private TlsVersionService service() {
        var source = new ResourceBundleMessageSource();
        source.setBasename("messages");
        source.setDefaultEncoding("UTF-8");
        source.setFallbackToSystemLocale(false);
        return new TlsVersionService(new MessageCatalog(source));
    }

    private TlsDetails evaluate(String negotiated, List<String> deprecated) {
        return service().evaluate(negotiated, "TLS_AES_256_GCM_SHA384", deprecated);
    }

    @Test
    @DisplayName("negocia 1.3 mas oferece 1.0/1.1 -> FRACO (o bug corrigido)")
    void negociado13ComDeprecadosOferecidosEhFraco() {
        TlsDetails r = evaluate("TLSv1.3", List.of("TLSv1.1", "TLSv1"));

        assertTrue(r.isWeakProtocol(),
                "1.0/1.1 aceitos ao lado do 1.3 é exposição — negociar 1.3 não absolve o servidor");
        assertEquals("TLSv1.3", r.getNegotiatedProtocol(),
                "o negociado real continua sendo mostrado como 1.3");
    }

    @Test
    @DisplayName("rótulo do achado nomeia os deprecados, não o negociado")
    void rotuloNomeiaOsDeprecados() {
        TlsDetails r = evaluate("TLSv1.3", List.of("TLSv1.1", "TLSv1"));

        assertEquals("TLSv1.1, TLSv1", r.getWeakProtocolLabel(),
                "estampar 'TLS fraco: TLSv1.3' confundiria — o problema são 1.0/1.1");
        assertTrue(r.getMessage().contains("TLSv1.1") && r.getMessage().contains("TLSv1"),
                "a mensagem do card precisa dizer quais protocolos velhos seguem aceitos");
    }

    @Test
    @DisplayName("negocia 1.3 e NÃO oferece deprecado -> seguro")
    void negociado13SemDeprecadosEhSeguro() {
        TlsDetails r = evaluate("TLSv1.3", List.of());

        assertFalse(r.isWeakProtocol(),
                "um servidor que só fala 1.2/1.3 não pode ser marcado fraco");
        assertEquals("TLSv1.3", r.getWeakProtocolLabel());
    }

    @Test
    @DisplayName("melhor protocolo já é fraco -> FRACO mesmo sem sondar deprecados")
    void negociadoFracoEhFraco() {
        TlsDetails r = evaluate("TLSv1", List.of("TLSv1"));
        assertTrue(r.isWeakProtocol());
    }

    @Test
    @DisplayName("negocia 1.2 sem deprecados -> seguro")
    void negociado12EhSeguro() {
        assertFalse(evaluate("TLSv1.2", List.of()).isWeakProtocol());
    }

    @Test
    @DisplayName("TlsDetails de 4 args mantém compatibilidade: sem deprecados, não é fraco por lista")
    void construtor4ArgsCompativel() {
        TlsDetails r = new TlsDetails("TLSv1.3", "TLS_AES_256_GCM_SHA384", false, "OK");
        assertTrue(r.getDeprecatedProtocolsOffered().isEmpty(),
                "call sites antigos (N/A, erros, testes) continuam válidos com lista vazia");
        assertEquals("TLSv1.3", r.getWeakProtocolLabel());
    }
}
