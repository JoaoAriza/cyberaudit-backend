package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.SSLInfo;
import org.springframework.stereotype.Service;

import javax.net.ssl.HttpsURLConnection;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;

@Service
public class SSLService {

    public SSLInfo checkSSL(String urlString) {

        if (urlString == null || urlString.isBlank()) {
            return new SSLInfo(false, false, null, 0, "URL vazia");
        }

        if (!urlString.startsWith("https://")) {
            return new SSLInfo(false, false, null, 0, "Site não usa HTTPS");
        }

        try {
            URL url = new URL(urlString);
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.setConnectTimeout(8000);
            connection.setReadTimeout(8000);
            connection.connect();

            Certificate[] certs = connection.getServerCertificates();
            X509Certificate cert = (X509Certificate) certs[0];

            LocalDate expiration = cert.getNotAfter()
                    .toInstant()
                    .atZone(ZoneId.systemDefault())
                    .toLocalDate();

            // notBefore junto com notAfter dá a vida útil TOTAL, que o score usa para
            // julgar a expiração em proporção. Sem isso, 30 dias restantes num
            // certificado Let's Encrypt (90 dias de vida) seriam lidos como risco,
            // quando são exatamente o momento em que o certbot renova.
            LocalDate issued = cert.getNotBefore()
                    .toInstant()
                    .atZone(ZoneId.systemDefault())
                    .toLocalDate();

            long daysRemaining      = ChronoUnit.DAYS.between(LocalDate.now(), expiration);
            long totalValidityDays  = Math.max(0, ChronoUnit.DAYS.between(issued, expiration));
            boolean valid = daysRemaining > 0;

            String message = valid ? "Certificado válido" : "Certificado expirado";

            return new SSLInfo(true, valid, expiration.toString(), daysRemaining, message,
                    totalValidityDays);

        } catch (Exception e) {
            return new SSLInfo(true, false, null, 0, "Erro ao verificar certificado: " + e.getMessage());
        }
    }
}