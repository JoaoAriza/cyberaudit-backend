package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.PortFinding;
import org.springframework.stereotype.Service;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
public class PortScanService {

    private static final List<Integer> COMMON_PORTS = List.of(
            21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 8080,
            1433, 1521, 3306, 5432, 6379, 27017
    );

    private static final Map<Integer, String> SERVICE_NAMES = Map.ofEntries(
            Map.entry(21, "FTP"),
            Map.entry(22, "SSH"),
            Map.entry(23, "TELNET"),
            Map.entry(25, "SMTP"),
            Map.entry(53, "DNS"),
            Map.entry(80, "HTTP"),
            Map.entry(110, "POP3"),
            Map.entry(143, "IMAP"),
            Map.entry(443, "HTTPS"),
            Map.entry(465, "SMTPS"),
            Map.entry(587, "SMTP Submission"),
            Map.entry(993, "IMAPS"),
            Map.entry(995, "POP3S"),
            Map.entry(8080, "HTTP Alt"),
            Map.entry(1433, "MS SQL Server"),
            Map.entry(1521, "Oracle"),
            Map.entry(3306, "MySQL"),
            Map.entry(5432, "PostgreSQL"),
            Map.entry(6379, "Redis"),
            Map.entry(27017, "MongoDB")
    );

    public List<PortFinding> scanCommonPorts(String host) {
        List<PortFinding> findings = new ArrayList<>();
        if (host == null || host.isBlank()) return findings;

        for (int port : COMMON_PORTS) {
            boolean open = isPortOpen(host, port, 180);
            if (open) {
                findings.add(buildFinding(port));
            }
        }
        return findings;
    }

    private boolean isPortOpen(String host, int port, int timeoutMs) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), 180);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private PortFinding buildFinding(int port) {
        String service = SERVICE_NAMES.getOrDefault(port, "UNKNOWN");

        // severidade + recomendações simples (v1)
        if (port == 23) {
            return new PortFinding(port, service, true, "HIGH",
                    "Telnet transmite dados sem criptografia (credenciais podem vazar).",
                    "Desabilitar TELNET e usar SSH (porta 22) com configurações seguras."
            );
        }

        if (port == 21) {
            return new PortFinding(port, service, true, "HIGH",
                    "FTP pode expor credenciais/dados se não estiver protegido.",
                    "Desabilitar FTP ou migrar para SFTP/FTPS e restringir acesso por firewall."
            );
        }

        if (port == 3306 || port == 5432 || port == 1433 || port == 1521 || port == 27017 || port == 6379) {
            return new PortFinding(port, service, true, "HIGH",
                    "Serviço de banco/daemon exposto publicamente aumenta risco de ataque e vazamento.",
                    "Restringir a rede (firewall/VPC), expor apenas internamente e exigir autenticação forte."
            );
        }

        if (port == 22) {
            return new PortFinding(port, service, true, "MEDIUM",
                    "SSH exposto pode ser alvo de brute force se não estiver protegido.",
                    "Restringir por IP, desabilitar login por senha, usar chaves e MFA quando possível."
            );
        }

        if (port == 80 || port == 8080) {
            return new PortFinding(port, service, true, "LOW",
                    "HTTP exposto pode permitir acesso sem criptografia dependendo da configuração.",
                    "Forçar HTTPS com redirect 301 e habilitar HSTS."
            );
        }

        if (port == 443) {
            return new PortFinding(port, service, true, "INFO",
                    "HTTPS aberto (esperado).",
                    "Manter TLS atualizado e certificado válido."
            );
        }

        return new PortFinding(port, service, true, "LOW",
                "Porta aberta detectada.",
                "Verificar se o serviço é necessário; se não, fechar/restringir."
        );
    }
}


