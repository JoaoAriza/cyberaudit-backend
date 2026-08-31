package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.TlsDetails;
import org.springframework.stereotype.Service;

import javax.net.ssl.*;
import java.security.cert.X509Certificate;

@Service
public class TlsVersionService {

    private final MessageCatalog catalog;

    public TlsVersionService(MessageCatalog catalog) {
        this.catalog = catalog;
    }

    public TlsDetails inspect(String host, int port) {
        if (host == null || host.isBlank())
            return new TlsDetails("UNKNOWN", "UNKNOWN", false, catalog.desc("TLS_INVALID_HOST"));

        try {
            SSLContext ctx = buildPermissiveContext();
            SSLSocketFactory factory = ctx.getSocketFactory();

            try (SSLSocket socket = (SSLSocket) factory.createSocket(host, port)) {
                socket.setSoTimeout(6000);
                socket.startHandshake();

                SSLSession session  = socket.getSession();
                String protocol     = session.getProtocol();
                String cipher       = session.getCipherSuite();
                boolean weak        = isWeak(protocol);

                return new TlsDetails(protocol, cipher, weak, buildMessage(protocol, cipher, weak));
            }

        } catch (Exception e) {
            return new TlsDetails("UNKNOWN", "UNKNOWN", false,
                    catalog.desc("TLS_INSPECT_FAILED", e.getMessage()));
        }
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