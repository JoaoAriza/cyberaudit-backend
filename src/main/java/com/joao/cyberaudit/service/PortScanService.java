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
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

@Service
public class PortScanService {

    private static final List<PortConfig> PORT_CONFIGS = List.of(
            // Protocolo / Serviço          port  sev        connectMs  banner?
            new PortConfig(21,   "FTP",                    "HIGH",    1500, true),
            new PortConfig(22,   "SSH",                    "MEDIUM",  1500, true),
            new PortConfig(23,   "TELNET",                 "HIGH",    1200, true),
            new PortConfig(25,   "SMTP",                   "LOW",     1500, true),
            new PortConfig(53,   "DNS",                    "LOW",     1200, false),
            new PortConfig(80,   "HTTP",                   "LOW",     1500, false),
            new PortConfig(110,  "POP3",                   "LOW",     1500, true),
            new PortConfig(143,  "IMAP",                   "LOW",     1500, true),
            new PortConfig(443,  "HTTPS",                  "INFO",    1800, false),
            new PortConfig(465,  "SMTPS",                  "LOW",     1500, true),
            new PortConfig(587,  "SMTP (Submission)",      "LOW",     1500, true),
            new PortConfig(993,  "IMAPS",                  "LOW",     1500, false),
            new PortConfig(995,  "POP3S",                  "LOW",     1500, false),
            // DB ports — requerem banner para confirmar abertura real
            new PortConfig(1433, "MS SQL Server",          "HIGH",    2000, true),
            new PortConfig(1521, "Oracle DB",              "HIGH",    2000, true),
            new PortConfig(3306, "MySQL",                  "HIGH",    2000, true),
            new PortConfig(5432, "PostgreSQL",             "HIGH",    2000, true),
            new PortConfig(6379, "Redis",                  "HIGH",    2000, true),
            new PortConfig(8080, "HTTP Alt",               "LOW",     1500, false),
            new PortConfig(8443, "HTTPS Alt",              "INFO",    1800, false),
            new PortConfig(9200, "Elasticsearch",          "HIGH",    2000, true)
    );

    /**
     * Portas cujo simples TCP-connect NÃO confirma abertura.
     * Exigem leitura de banner — CDNs/proxies aceitam TCP mas não entregam banner de DB.
     */
    private static final Set<Integer> BANNER_REQUIRED_PORTS = Set.of(
            1433, 1521, 3306, 5432, 6379, 9200, 21, 23, 25, 110, 143, 465, 587
    );

    public List<PortFinding> scanCommonPorts(String host) {
        InetAddress addr;
        try { addr = InetAddress.getByName(host); }
        catch (Exception e) { return Collections.emptyList(); }

        ExecutorService pool = Executors.newFixedThreadPool(20);
        Semaphore sem = new Semaphore(10);
        AtomicInteger timeouts = new AtomicInteger(0);

        try {
            List<CompletableFuture<PortFinding>> futures = PORT_CONFIGS.stream()
                    .map(cfg -> CompletableFuture.supplyAsync(
                            () -> probe(addr, host, cfg, sem, timeouts), pool))
                    .collect(Collectors.toList());

            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                    .get(20, TimeUnit.SECONDS);

            return futures.stream()
                    .map(f -> f.getNow(null))
                    .filter(Objects::nonNull)
                    .filter(f -> "OPEN".equals(f.getState()))
                    .sorted(Comparator.comparingInt(PortFinding::getPort))
                    .collect(Collectors.toList());

        } catch (Exception ignored) {
            return Collections.emptyList();
        } finally {
            pool.shutdownNow();
        }
    }

    private PortFinding probe(InetAddress addr, String host, PortConfig cfg,
                              Semaphore sem, AtomicInteger timeouts) {
        boolean acquired = false;
        long start = System.currentTimeMillis();
        try {
            acquired = sem.tryAcquire(2, TimeUnit.SECONDS);
            if (!acquired) return null;

            int timeout = cfg.connectMs() + (timeouts.get() >= 5 ? 500 : 0);

            // ── Passo 1: TCP connect ────────────────────────────────────
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(addr, cfg.port()), timeout);
                long latency = System.currentTimeMillis() - start;
                socket.setSoTimeout(1500);

                // ── Passo 2: Banner verification para portas críticas ───
                if (BANNER_REQUIRED_PORTS.contains(cfg.port())) {
                    String banner = readBanner(host, cfg.port(), socket);
                    if (banner == null) {
                        // TCP conectou mas sem banner = CDN/proxy/firewall absorvendo
                        // Não reportar como OPEN — é um falso positivo
                        return null;
                    }
                    return buildFinding(cfg, latency, banner, "CONFIRMED");
                }

                // ── Passo 3: HTTP/HTTPS evidence ───────────────────────
                if (cfg.port() == 80 || cfg.port() == 8080) {
                    String evidence = httpEvidence(host, cfg.port(), false);
                    return buildFinding(cfg, latency, evidence, "HTTP");
                }
                if (cfg.port() == 443 || cfg.port() == 8443 || cfg.port() == 993 || cfg.port() == 995) {
                    String evidence = httpEvidence(host, cfg.port(), true);
                    return buildFinding(cfg, latency, evidence, "TLS");
                }

                // DNS, outros — TCP-connect suficiente
                return buildFinding(cfg, latency, null, "TCP");

            } catch (SocketTimeoutException te) {
                timeouts.incrementAndGet();
                return null; // FILTERED — não reportar
            } catch (ConnectException ce) {
                return null; // CLOSED — não reportar
            }

        } catch (Exception e) {
            return null;
        } finally {
            if (acquired) sem.release();
        }
    }

    /**
     * Tenta ler um banner do socket após conexão TCP.
     * Retorna null se nenhum banner for recebido dentro do timeout.
     * CDNs/proxies geralmente não enviam banner de aplicação (DB, SMTP, etc.)
     */
    private String readBanner(String host, int port, Socket socket) {
        try {
            socket.setSoTimeout(2000);

            // Redis: envia PING para provocar resposta
            if (port == 6379) {
                socket.getOutputStream().write("PING\r\n".getBytes(StandardCharsets.UTF_8));
                socket.getOutputStream().flush();
            }

            // MySQL: envia request de handshake inicial
            if (port == 3306) {
                // MySQL envia greeting automaticamente — apenas lê
            }

            BufferedReader br = new BufferedReader(
                    new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            String line = br.readLine();

            if (line == null || line.isBlank()) return null;

            // Valida que o banner faz sentido para o serviço
            return validateBanner(port, line.trim());

        } catch (Exception e) {
            return null; // timeout ou erro = banner não confirmado
        }
    }

    /**
     * Valida se o banner recebido é consistente com o serviço esperado.
     * Evita classificar respostas HTTP de CDN como banner de DB.
     */
    private String validateBanner(int port, String banner) {
        String lower = banner.toLowerCase();

        // Rejeita respostas HTTP genéricas de CDN/proxy em portas de DB
        if (lower.startsWith("http/") || lower.contains("cloudflare") ||
                lower.contains("blocked") || lower.contains("access denied")) {
            return null;
        }

        return switch (port) {
            case 21  -> lower.startsWith("220") ? trim(banner, 120) : null;
            case 23  -> banner.length() > 2     ? trim(banner, 120) : null;
            case 25  -> lower.startsWith("220") ? trim(banner, 120) : null;
            case 110 -> lower.startsWith("+ok")  ? trim(banner, 120) : null;
            case 143 -> lower.startsWith("* ok") ? trim(banner, 120) : null;
            case 465, 587 -> lower.startsWith("220") ? trim(banner, 120) : null;
            case 1433 -> banner.length() > 4    ? "MS SQL Server respondeu (banner binário)" : null;
            case 1521 -> banner.length() > 4    ? "Oracle respondeu (banner binário)" : null;
            case 3306 -> banner.length() > 4 && !lower.startsWith("http")
                    ? "MySQL respondeu (handshake detectado)" : null;
            case 5432 -> banner.length() > 4    ? "PostgreSQL respondeu (banner detectado)" : null;
            case 6379 -> lower.contains("+pong") || lower.startsWith("-")
                    ? "Redis respondeu: " + trim(banner, 80) : null;
            case 9200 -> lower.contains("elasticsearch") || lower.contains("{")
                    ? "Elasticsearch respondeu: " + trim(banner, 100) : null;
            default -> banner.length() > 2 ? trim(banner, 120) : null;
        };
    }

    private String httpEvidence(String host, int port, boolean tls) {
        try {
            if (!tls) {
                try (Socket s = new Socket()) {
                    s.connect(new InetSocketAddress(host, port), 1500);
                    s.setSoTimeout(1500);
                    s.getOutputStream().write(
                            ("HEAD / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n")
                                    .getBytes(StandardCharsets.UTF_8));
                    s.getOutputStream().flush();
                    return parseHttpEvidence(s);
                }
            }
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            try (SSLSocket ssl = (SSLSocket) factory.createSocket()) {
                ssl.connect(new InetSocketAddress(host, port), 1800);
                ssl.setSoTimeout(1500);
                ssl.startHandshake();
                ssl.getOutputStream().write(
                        ("HEAD / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n")
                                .getBytes(StandardCharsets.UTF_8));
                ssl.getOutputStream().flush();
                return parseHttpEvidence(ssl);
            }
        } catch (Exception e) { return null; }
    }

    private String parseHttpEvidence(Socket s) {
        try {
            BufferedReader br = new BufferedReader(
                    new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
            String status = null, server = null, line;
            while ((line = br.readLine()) != null) {
                if (status == null && line.startsWith("HTTP/")) status = line;
                if (line.toLowerCase().startsWith("server:")) server = line;
                if (line.isBlank()) break;
            }
            if (status != null || server != null) {
                return (status != null ? trim(status, 60) : "") +
                        (server != null ? " | " + trim(server, 80) : "");
            }
        } catch (Exception ignored) {}
        return null;
    }

    private PortFinding buildFinding(PortConfig cfg, long latency,
                                     String evidence, String method) {
        return new PortFinding(
                impactFor(cfg.port(), cfg.service()),
                recommendationFor(cfg.port(), cfg.service()),
                cfg.port(),
                cfg.service(),
                "OPEN",
                cfg.severity(),
                latency,
                evidence != null ? evidence : (method != null ? "Conectado via " + method : null)
        );
    }

    private String trim(String s, int max) {
        if (s == null) return null;
        s = s.trim();
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }

    private String impactFor(int port, String service) {
        return switch (port) {
            case 21   -> "FTP exposto: transmite credenciais em texto plano; permite enumeração e exfiltração de arquivos.";
            case 22   -> "SSH exposto aumenta superfície de ataque (bruteforce, credenciais fracas, exploits de versão).";
            case 23   -> "TELNET: protocolo sem criptografia. Credenciais e dados em texto plano na rede.";
            case 25   -> "SMTP aberto pode ser usado para relay de spam ou enumeração de usuários (VRFY/EXPN).";
            case 53   -> "DNS exposto permite enumeração de registros e pode ser usado em ataques de amplificação.";
            case 1433 -> "MS SQL Server exposto: risco de acesso não autorizado, execução de queries e exfiltração.";
            case 1521 -> "Oracle DB exposto: acesso não autorizado a dados críticos e possível RCE via procedures.";
            case 3306 -> "MySQL exposto: acesso direto ao banco sem camada de aplicação como proteção.";
            case 5432 -> "PostgreSQL exposto: acesso não autorizado a dados e possível RCE via extensões.";
            case 6379 -> "Redis sem auth é crítico: leitura/escrita irrestrita, possível RCE via CONFIG SET.";
            case 9200 -> "Elasticsearch exposto: leitura/alteração de índices, exfiltração de dados em massa.";
            case 80, 8080 -> "HTTP exposto; risco depende de autenticação, vulnerabilidades e conteúdo do app.";
            case 443, 8443 -> "HTTPS exposto é esperado; risco depende de configuração TLS e do app.";
            default   -> "Serviço " + service + " exposto pode ampliar a superfície de ataque.";
        };
    }

    private String recommendationFor(int port, String service) {
        return switch (port) {
            case 21   -> "Desative FTP. Use SFTP (porta 22) ou FTPS. Restrinja por firewall/VPN.";
            case 22   -> "Use autenticação por chave (desative senha). Restrinja IPs via firewall. Habilite fail2ban.";
            case 23   -> "Desative TELNET imediatamente. Substitua por SSH. Bloqueie no firewall.";
            case 25   -> "Restrinja relay. Habilite autenticação. Bloqueie se não for servidor de email.";
            case 1433, 1521, 3306, 5432 -> "Nunca exponha DB na internet. Restrinja a IPs internos/VPN. Habilite autenticação forte e auditoria.";
            case 6379 -> "Exija AUTH/ACL. Vincule ao loopback (127.0.0.1). Coloque atrás de VPN. Desative comandos perigosos.";
            case 9200 -> "Habilite autenticação (X-Pack/Security). Coloque atrás de VPN/rede interna. Nunca exponha publicamente.";
            case 80, 8080 -> "Redirecione para HTTPS. Aplique WAF. Mantenha app e dependências atualizadas.";
            case 443, 8443 -> "Configure TLS forte (1.2+), HSTS, certificado válido e atualize dependências.";
            default   -> "Feche se não necessário. Se necessário, restrinja por IP e use autenticação forte.";
        };
    }

    private record PortConfig(int port, String service, String severity,
                              int connectMs, boolean requiresBanner) {}
}
