package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.TlsDetails;
import org.springframework.stereotype.Service;

import javax.net.ssl.*;
import java.security.cert.X509Certificate;

@Service
public class TlsVersionService {

    public TlsDetails inspect(String host, int port) {
        if (host == null || host.isBlank())
            return new TlsDetails("UNKNOWN", "UNKNOWN", false, "Host inválido");

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
                    "Não foi possível inspecionar TLS: " + e.getMessage());
        }
    }

    private boolean isWeak(String p) {
        return p != null && (p.equals("TLSv1") || p.equals("TLSv1.1") || p.equals("SSLv3"));
    }

    private String buildMessage(String protocol, String cipher, boolean weak) {
        if (weak) return protocol + " é deprecated (RFC 8996). Vulnerável a POODLE/BEAST.";
        if ("TLSv1.2".equals(protocol)) return "TLS 1.2 — seguro. TLS 1.3 oferece melhor forward secrecy.";
        if ("TLSv1.3".equals(protocol)) return "TLS 1.3 — protocolo atual. Cipher: " + cipher;
        return "Protocolo: " + protocol + ". Cipher: " + cipher;
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