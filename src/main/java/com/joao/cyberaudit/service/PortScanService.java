package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.PortFinding;
import org.springframework.stereotype.Service;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

@Service
public class PortScanService {

    // Lista “comum” — não varre 65k portas (mais seguro e mais rápido)
    private static final List<Integer> COMMON_PORTS = List.of(
            21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587,
            993, 995, 1433, 1521, 3306, 5432, 6379, 8080, 8443, 9200
    );

    public List<PortFinding> scanCommonPorts(String host) {
        // limites pra não “matar” a infra e evitar timeouts no Render
        int threads = 30; // bom equilíbrio
        ExecutorService pool = Executors.newFixedThreadPool(threads);

        try {
            List<CompletableFuture<PortFinding>> futures = COMMON_PORTS.stream()
                    .map(port -> CompletableFuture.supplyAsync(() -> scanOne(host, port), pool))
                    .collect(Collectors.toList());

            List<PortFinding> results = futures.stream()
                    .map(f -> {
                        try { return f.get(8, TimeUnit.SECONDS); } // tempo total por porta
                        catch (Exception e) { return null; }
                    })
                    .filter(Objects::nonNull)
                    .collect(Collectors.toList());

            // normalmente você só quer mostrar OPEN (e opcionalmente FILTERED)
            return results.stream()
                    .filter(r -> "OPEN".equals(r.getState()))
                    .sorted(Comparator.comparingInt(PortFinding::getPort))
                    .collect(Collectors.toList());

        } finally {
            pool.shutdownNow();
        }
    }

    private PortFinding scanOne(String host, int port) {
        String guessedService = guessService(port);

        // timeouts dinâmicos (opção 5)
        int connectTimeoutMs = connectTimeoutFor(port);
        int readTimeoutMs = readTimeoutFor(port);

        long start = System.currentTimeMillis();
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), connectTimeoutMs);
            long latency = System.currentTimeMillis() - start;
            socket.setSoTimeout(readTimeoutMs);

            // OPEN -> tentar evidência leve (opção 2)
            String evidence = probeEvidence(host, port, socket);
            String severity = classifySeverity(port, guessedService);

            // Novo: impact / recommendation (básico, mas útil pro relatório)
            String impact = impactFor(port, guessedService);
            String recommendation = recommendationFor(port, guessedService);

            return new PortFinding(
                    impact,
                    recommendation,
                    port,
                    guessedService,
                    "OPEN",
                    severity,
                    Long.valueOf(latency),
                    evidence
            );

        } catch (ConnectException ce) {
            long latency = System.currentTimeMillis() - start;

            return new PortFinding(
                    "N/A",
                    "N/A",
                    port,
                    guessedService,
                    "CLOSED",
                    "INFO",
                    Long.valueOf(latency),
                    null
            );

        } catch (SocketTimeoutException te) {
            long latency = System.currentTimeMillis() - start;

            return new PortFinding(
                    "Sem resposta no timeout (pode ser firewall/CDN/edge).",
                    "Se for serviço esperado, liberar a porta no firewall/CDN; se não for, manter bloqueado.",
                    port,
                    guessedService,
                    "FILTERED",
                    "INFO",
                    Long.valueOf(latency),
                    "Sem resposta no timeout (pode ser firewall/CDN/edge)"
            );

        } catch (Exception e) {
            long latency = System.currentTimeMillis() - start;

            return new PortFinding(
                    "Falha ao testar a porta (erro inesperado).",
                    "Verifique DNS, conectividade e regras de firewall/CDN; tente novamente.",
                    port,
                    guessedService,
                    "FILTERED",
                    "INFO",
                    Long.valueOf(latency),
                    "Erro: " + e.getClass().getSimpleName()
            );
        }
    }

    private String probeEvidence(String host, int port, Socket socket) {
        try {
            // HTTP: HEAD request (bem leve)
            if (port == 80 || port == 8080 || port == 8000) {
                return httpHeadEvidence(host, port, false);
            }
            if (port == 443 || port == 8443) {
                return httpHeadEvidence(host, port, true);
            }

            // FTP / SMTP / POP3 / IMAP: lê banner (1 linha, curto)
            if (port == 21 || port == 25 || port == 110 || port == 143 || port == 587) {
                BufferedReader br = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
                String line = br.readLine();
                if (line != null && !line.isBlank()) return "Banner: " + trim(line, 140);
            }

            // Redis às vezes manda banner/erro em texto, mas nem sempre.
            // MySQL/SQLServer/Oracle geralmente protocolo binário -> não force.
            return null;

        } catch (Exception ignored) {
            return null;
        }
    }

    private String httpHeadEvidence(String host, int port, boolean tls) {
        // Faz HEAD “na mão” para evitar dependências e manter simples
        try {
            if (!tls) {
                try (Socket s = new Socket()) {
                    s.connect(new InetSocketAddress(host, port), 1200);
                    s.setSoTimeout(1200);

                    OutputStream os = s.getOutputStream();
                    os.write(("HEAD / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n")
                            .getBytes(StandardCharsets.UTF_8));
                    os.flush();

                    BufferedReader br = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
                    String line;
                    String server = null;
                    String status = null;
                    while ((line = br.readLine()) != null) {
                        if (status == null && line.startsWith("HTTP/")) status = line;
                        if (line.toLowerCase().startsWith("server:")) server = line;
                        if (line.isBlank()) break;
                    }
                    if (status != null || server != null) {
                        return (status != null ? trim(status, 80) : "") +
                                (server != null ? " | " + trim(server, 120) : "");
                    }
                }
                return null;
            }

            // TLS: abre SSLSocket e faz HEAD
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            try (SSLSocket ssl = (SSLSocket) factory.createSocket()) {
                ssl.connect(new InetSocketAddress(host, port), 1500);
                ssl.setSoTimeout(1500);
                ssl.startHandshake();

                OutputStream os = ssl.getOutputStream();
                os.write(("HEAD / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n")
                        .getBytes(StandardCharsets.UTF_8));
                os.flush();

                BufferedReader br = new BufferedReader(new InputStreamReader(ssl.getInputStream(), StandardCharsets.UTF_8));
                String line;
                String server = null;
                String status = null;
                while ((line = br.readLine()) != null) {
                    if (status == null && line.startsWith("HTTP/")) status = line;
                    if (line.toLowerCase().startsWith("server:")) server = line;
                    if (line.isBlank()) break;
                }
                if (status != null || server != null) {
                    return (status != null ? trim(status, 80) : "") +
                            (server != null ? " | " + trim(server, 120) : "");
                }
            }
            return null;

        } catch (Exception e) {
            return null;
        }
    }

    private String guessService(int port) {
        return switch (port) {
            case 21 -> "FTP";
            case 22 -> "SSH";
            case 23 -> "TELNET";
            case 25 -> "SMTP";
            case 53 -> "DNS";
            case 80 -> "HTTP";
            case 110 -> "POP3";
            case 143 -> "IMAP";
            case 443 -> "HTTPS";
            case 465 -> "SMTPS";
            case 587 -> "SMTP (Submission)";
            case 993 -> "IMAPS";
            case 995 -> "POP3S";
            case 1433 -> "MS SQL Server";
            case 1521 -> "Oracle";
            case 3306 -> "MySQL";
            case 5432 -> "PostgreSQL";
            case 6379 -> "Redis";
            case 8080 -> "HTTP Alt";
            case 8443 -> "HTTPS Alt";
            case 9200 -> "Elasticsearch";
            default -> "Unknown";
        };
    }

    private String classifySeverity(int port, String service) {
        // Ajuste ao seu gosto. Aqui vai uma base bem aceitável pra relatório:
        if (port == 21 || port == 23) return "HIGH"; // FTP/Telnet
        if (port == 1433 || port == 1521 || port == 3306 || port == 5432 || port == 6379 || port == 9200) return "HIGH"; // DB/Redis/ES exposto
        if (port == 22) return "MEDIUM"; // SSH exposto pode ser ok, mas é sensível
        if (port == 80 || port == 8080) return "LOW"; // pode ser normal
        if (port == 443 || port == 8443) return "INFO";
        return "LOW";
    }

    private int connectTimeoutFor(int port) {
        // timeouts dinâmicos: DB costuma ser mais lento/filtrado
        if (port == 1433 || port == 1521 || port == 3306 || port == 5432 || port == 6379 || port == 9200) return 1800;
        if (port == 443 || port == 8443) return 1600;
        return 1200;
    }

    private int readTimeoutFor(int port) {
        if (port == 80 || port == 8080 || port == 443 || port == 8443) return 1500;
        return 1200;
    }

    private String trim(String s, int max) {
        if (s == null) return null;
        s = s.trim();
        return s.length() <= max ? s : s.substring(0, max);
    }

    // ----------------------------
    // Impact / Recommendation (básico)
    // ----------------------------
    private String impactFor(int port, String service) {
        // Impacto bem direto pro relatório
        if (port == 21) return "FTP exposto pode permitir vazamento de arquivos e credenciais (protocolo inseguro).";
        if (port == 23) return "Telnet exposto transmite credenciais em texto plano e facilita acesso indevido.";
        if (port == 1433 || port == 1521 || port == 3306 || port == 5432)
            return "Banco de dados exposto pode permitir acesso não autorizado, enumeração e vazamento de dados.";
        if (port == 6379) return "Redis exposto frequentemente permite leitura/escrita de dados e execução de comandos.";
        if (port == 9200) return "Elasticsearch exposto pode permitir leitura/alteração de índices e vazamento de dados.";
        if (port == 22) return "SSH exposto aumenta superfície de ataque (bruteforce/credenciais fracas).";
        if (port == 80 || port == 8080) return "HTTP exposto é comum; risco depende de autenticação e vulnerabilidades do app.";
        if (port == 443 || port == 8443) return "HTTPS exposto é comum; risco depende de configuração e do app.";
        return "Serviço exposto pode aumentar a superfície de ataque dependendo da configuração.";
    }

    private String recommendationFor(int port, String service) {
        if (port == 21) return "Evite FTP: use SFTP/FTPS; restrinja por firewall/VPN e desabilite se não for necessário.";
        if (port == 23) return "Desabilite Telnet e use SSH; bloqueie a porta no firewall.";
        if (port == 1433 || port == 1521 || port == 3306 || port == 5432)
            return "Não exponha DB na internet: restrinja por firewall, permita apenas IPs internos/VPN e habilite autenticação forte.";
        if (port == 6379) return "Restrinja Redis a rede interna, exija auth/ACL e bloqueie acesso público.";
        if (port == 9200) return "Restrinja Elasticsearch, exija autenticação, e bloqueie acesso público; coloque atrás de VPN/rede interna.";
        if (port == 22) return "Restrinja SSH por IP/VPN, desabilite senha (use chave), e habilite rate limit/fail2ban.";
        if (port == 80 || port == 8080) return "Se possível redirecione para HTTPS, aplique WAF/CDN e mantenha o app atualizado.";
        if (port == 443 || port == 8443) return "Habilite TLS forte, HSTS, e mantenha o app e dependências atualizadas.";
        return "Feche a porta se não for necessária; caso seja, restrinja por firewall e use autenticação forte.";
    }
}