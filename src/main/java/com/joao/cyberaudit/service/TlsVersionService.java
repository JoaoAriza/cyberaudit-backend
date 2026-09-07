package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.TlsDetails;
import org.springframework.stereotype.Service;

import javax.net.ssl.*;
import java.net.InetSocketAddress;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Service
public class TlsVersionService {

    /** Deprecados sondados ativamente, do mais novo ao mais antigo. */
    private static final List<String> DEPRECATED_PROBES = List.of("TLSv1.1", "TLSv1");

    static {
        reenableDeprecatedForProbing();
    }

    /**
     * O JDK 17 traz TLSv1 e TLSv1.1 em {@code jdk.tls.disabledAlgorithms}, então o
     * próprio cliente se recusa a enviar um ClientHello nessas versões — e "não
     * consigo perguntar" era lido como "o servidor não oferece". Esse era o ponto
     * cego: um alvo atrás de Cloudflare (mínimo TLS 1.0 por padrão) aceita 1.0/1.1
     * e o scanner reportava SECURE, porque a negociação sempre fecha em 1.3.
     *
     * Removemos SÓ TLSv1/TLSv1.1 da lista (SSLv3, RC4, 3DES seguem banidos). O
     * efeito é global e vale a pena entender:
     *   - lado CLIENTE: os sockets de saída do processo passam a ACEITAR negociar
     *     1.0/1.1 se um alvo só oferecer isso — desejável num scanner (alcança o
     *     alvo em vez de falhar); os upstreams próprios (crt.sh, NVD) exigem 1.2+.
     *   - lado SERVIDOR: NENHUM efeito. disabledAlgorithms é piso, não teto:
     *     remover daqui não habilita 1.0/1.1 no listener — o servidor continua
     *     oferecendo só o que a config dele habilita (1.2/1.3).
     */
    private static void reenableDeprecatedForProbing() {
        String atual = Security.getProperty("jdk.tls.disabledAlgorithms");
        if (atual == null) return;
        String novo = Arrays.stream(atual.split(","))
                .map(String::trim)
                .filter(t -> !t.equalsIgnoreCase("TLSv1") && !t.equalsIgnoreCase("TLSv1.1"))
                .reduce((a, b) -> a + ", " + b).orElse("");
        Security.setProperty("jdk.tls.disabledAlgorithms", novo);
    }

    private final MessageCatalog catalog;

    public TlsVersionService(MessageCatalog catalog) {
        this.catalog = catalog;
    }

    public TlsDetails inspect(String host, int port) {
        if (host == null || host.isBlank())
            return new TlsDetails("UNKNOWN", "UNKNOWN", false, catalog.desc("TLS_INVALID_HOST"));

        try {
            SSLSocketFactory factory = buildPermissiveContext().getSocketFactory();

            String negotiated;
            String cipher;
            try (SSLSocket socket = (SSLSocket) factory.createSocket(host, port)) {
                socket.setSoTimeout(6000);
                socket.startHandshake();
                negotiated = socket.getSession().getProtocol();
                cipher     = socket.getSession().getCipherSuite();
            }

            List<String> deprecatedOffered = probeDeprecated(factory, host, port);
            return evaluate(negotiated, cipher, deprecatedOffered);

        } catch (Exception e) {
            return new TlsDetails("UNKNOWN", "UNKNOWN", false,
                    catalog.desc("TLS_INSPECT_FAILED", e.getMessage()));
        }
    }

    /**
     * Handshake forçando CADA protocolo deprecado: sucesso = o servidor oferece.
     * Só sonda o que a JVM realmente suporta — se um TLS futuro remover 1.0/1.1
     * de vez, o protocolo some de getSupportedProtocols e é pulado. Nunca marcamos
     * "não oferecido" a partir de algo que não conseguimos testar.
     */
    private List<String> probeDeprecated(SSLSocketFactory factory, String host, int port) {
        List<String> offered = new ArrayList<>();
        for (String proto : DEPRECATED_PROBES) {
            try (SSLSocket socket = (SSLSocket) factory.createSocket()) {
                if (!Arrays.asList(socket.getSupportedProtocols()).contains(proto)) continue;
                socket.connect(new InetSocketAddress(host, port), 6000);
                socket.setSoTimeout(6000);
                socket.setEnabledProtocols(new String[]{proto});
                socket.startHandshake();
                offered.add(proto);
            } catch (Exception ignored) {
                // handshake recusado, timeout ou reset: protocolo não oferecido.
            }
        }
        return offered;
    }

    /** Visível ao teste: separa a decisão (pura) da coleta de rede. */
    TlsDetails evaluate(String negotiated, String cipher, List<String> deprecatedOffered) {
        boolean weak = !deprecatedOffered.isEmpty() || isWeak(negotiated);

        String msg = deprecatedOffered.isEmpty()
                ? buildMessage(negotiated, cipher, weak)
                : catalog.desc("TLS_DEPRECATED_OFFERED",
                        String.join(", ", deprecatedOffered), negotiated);

        return new TlsDetails(negotiated, cipher, weak, msg, deprecatedOffered);
    }

    private boolean isWeak(String p) {
        return p != null && (p.equals("TLSv1") || p.equals("TLSv1.1") || p.equals("SSLv3"));
    }

    /**
     * Visível ao teste: esta mensagem vai inteira para o card de transporte, colada
     * a uma nota que o Frontend traduz. Em português dentro de um laudo em inglês,
     * a emenda ficava metade em cada idioma.
     */
    String buildMessage(String protocol, String cipher, boolean weak) {
        if (weak) return catalog.desc("TLS_DEPRECATED", protocol);
        if ("TLSv1.2".equals(protocol)) return catalog.desc("TLS_12");
        if ("TLSv1.3".equals(protocol)) return catalog.desc("TLS_13", cipher);
        return catalog.desc("TLS_OTHER", protocol, cipher);
    }

    private SSLContext buildPermissiveContext() throws Exception {
        TrustManager[] tm = { new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            public void checkClientTrusted(X509Certificate[] c, String a) {}
            public void checkServerTrusted(X509Certificate[] c, String a) {}
        }};
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tm, null);
        return ctx;
    }
}
