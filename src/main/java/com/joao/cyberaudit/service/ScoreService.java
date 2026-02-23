package com.joao.cyberaudit.service;

import com.joao.cyberaudit.model.*;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
public class ScoreService {

    public ScoreResult calculate(
            SSLInfo sslInfo,
            Map<String, String> headers,
            boolean redirectsToHttps,
            boolean activeMode,
            boolean inputSurfaceDetected,
            boolean dbErrorLeakageSuspected,
            boolean xssProbePerformed,
            boolean reflectedXssSuspected,
            List<PortFinding> openPorts
    ) {

        int score = 100;
        List<String> notes = new ArrayList<>();
        List<SecurityIssue> issues = new ArrayList<>();

        // ===== SSL (HTTPS suportado?) =====
        // A ideia é que sslInfo venha do teste em HTTPS (ex: https://site.com),
        // então "não suporta HTTPS" deve ser verdadeiro só quando HTTPS realmente falhar.
        if (!sslInfo.isHttps()) {
            score -= 40;
            notes.add("HTTPS não suportado: -40");

            issues.add(new SecurityIssue(
                    "NO_HTTPS_SUPPORT",
                    "HTTPS não suportado",
                    "HIGH",
                    "Dados podem ser interceptados por terceiros ao trafegar via HTTP.",
                    "Habilitar HTTPS com certificado válido (ex: Let's Encrypt) e servir o site em HTTPS."
            ));

        } else if (!sslInfo.isValid()) {
            score -= 35;
            notes.add("Certificado inválido/expirado/erro: -35");

            issues.add(new SecurityIssue(
                    "SSL_INVALID",
                    "Certificado SSL inválido",
                    "HIGH",
                    "Usuários podem receber alerta de segurança e a comunicação pode ficar insegura.",
                    "Renovar/configurar corretamente o certificado SSL e cadeia intermediária."
            ));

        } else {
            notes.add("HTTPS e certificado válido: OK");

            long days = sslInfo.getDaysRemaining();

            if (days <= 0) {
                score -= 35;
                notes.add("Certificado expirado: -35");

                issues.add(new SecurityIssue(
                        "SSL_EXPIRED",
                        "Certificado SSL expirado",
                        "HIGH",
                        "Navegadores podem bloquear o acesso ou alertar o usuário.",
                        "Renovar o certificado imediatamente."
                ));

            } else if (days <= 30) {
                score -= 20;
                notes.add("Certificado expira em até 30 dias: -20");

                issues.add(new SecurityIssue(
                        "SSL_EXPIRING_SOON",
                        "Certificado próximo da expiração",
                        "MEDIUM",
                        "Pode causar indisponibilidade/alertas se expirar.",
                        "Renovar certificado antes da expiração."
                ));

            } else if (days <= 90) {
                score -= 10;
                notes.add("Certificado expira em até 90 dias: -10");
            }
        }

        // ===== HTTPS forçado a partir de HTTP? =====
        // Mesmo suportando HTTPS, se não redirecionar HTTP->HTTPS, o usuário pode cair em HTTP.
        if (sslInfo.isHttps() && sslInfo.isValid() && !redirectsToHttps) {
            score -= 10;
            notes.add("Não força HTTPS a partir de HTTP: -10");

            issues.add(new SecurityIssue(
                    "HTTP_NOT_REDIRECTING",
                    "HTTP não redireciona para HTTPS",
                    "MEDIUM",
                    "Usuários podem acessar o site sem criptografia se digitarem http://.",
                    "Configurar redirect 301 de HTTP para HTTPS e habilitar HSTS."
            ));
        }

        // ===== PASSIVO: superfície de entrada =====
        // Não penaliza, apenas informa (bom pra relatório).
        if (inputSurfaceDetected) {
            notes.add("Superfície de entrada detectada (parâmetros na URL): INFO");
        }

        // ===== ATIVO (opt-in): DB error leakage =====
        // Penaliza somente se activeMode=true.
        if (activeMode && dbErrorLeakageSuspected) {
            score -= 15;
            notes.add("Possível exposição de erro de banco/SQL (modo ativo): -15");

            issues.add(new SecurityIssue(
                    "DB_ERROR_LEAKAGE_SUSPECTED",
                    "Possível exposição de erro de banco (DB error leakage)",
                    "HIGH",
                    "Mensagens detalhadas de erro podem revelar estrutura do banco e facilitar ataques. Isso não confirma SQLi, mas indica falha de tratamento de erros.",
                    "Ocultar erros detalhados em produção, retornar mensagens genéricas, registrar erros apenas no servidor e usar queries parametrizadas."
            ));
        }

        if (activeMode && xssProbePerformed && reflectedXssSuspected) {
            score -= 25;
            notes.add("Suspeita de Reflected XSS (marcador refletido no HTML): -25");

            issues.add(new SecurityIssue(
                    "REFLECTED_XSS_SUSPECTED",
                    "Suspeita de Reflected XSS (marcador refletido)",
                    "HIGH",
                    "O conteúdo de entrada parece ser refletido na página sem escape adequado. Isso pode permitir execução de scripts dependendo do contexto.",
                    "Aplicar output encoding (escape) adequado, validar/normalizar inputs e implementar CSP restritiva."
            ));
        }

        // ===== HEADERS =====
        for (Map.Entry<String, String> entry : headers.entrySet()) {

            String header = entry.getKey();
            String status = entry.getValue();
            if (status == null) continue;

            if (header.equalsIgnoreCase("error")) {
                score -= 15;
                notes.add("Erro ao buscar headers: -15");
                continue;
            }

            // --- HSTS ---
            if (header.equalsIgnoreCase("Strict-Transport-Security")) {
                if (status.startsWith("MISSING")) {
                    score -= 10;
                    notes.add("HSTS ausente: -10");

                    issues.add(new SecurityIssue(
                            "HSTS_MISSING",
                            "Strict-Transport-Security ausente",
                            "HIGH",
                            "Ataques downgrade para HTTP podem ocorrer mesmo com HTTPS disponível.",
                            "Adicionar header: Strict-Transport-Security: max-age=31536000; includeSubDomains"
                    ));
                } else if (status.startsWith("WEAK")) {
                    score -= 5;
                    notes.add("HSTS fraco: -5");

                    issues.add(new SecurityIssue(
                            "HSTS_WEAK",
                            "Strict-Transport-Security fraco",
                            "MEDIUM",
                            "Configuração incompleta pode reduzir a proteção contra downgrade.",
                            "Garantir max-age adequado (ex: 31536000) e considerar includeSubDomains."
                    ));
                } else if (status.startsWith("UNKNOWN")) {
                    score -= 3;
                    notes.add("HSTS valor incomum: -3");
                }
            }

            // --- X-Content-Type-Options ---
            if (header.equalsIgnoreCase("X-Content-Type-Options")) {
                if (status.startsWith("MISSING")) {
                    score -= 10;
                    notes.add("X-Content-Type-Options ausente: -10");

                    issues.add(new SecurityIssue(
                            "CONTENT_TYPE_MISSING",
                            "X-Content-Type-Options ausente",
                            "MEDIUM",
                            "Pode permitir MIME sniffing e execução indevida em alguns cenários.",
                            "Adicionar header: X-Content-Type-Options: nosniff"
                    ));
                } else if (status.startsWith("WEAK")) {
                    score -= 5;
                    notes.add("X-Content-Type-Options fraco: -5");

                    issues.add(new SecurityIssue(
                            "CONTENT_TYPE_WEAK",
                            "X-Content-Type-Options fraco",
                            "LOW",
                            "Valor não recomendado reduz a proteção contra MIME sniffing.",
                            "Usar exatamente: X-Content-Type-Options: nosniff"
                    ));
                } else if (status.startsWith("UNKNOWN")) {
                    score -= 3;
                    notes.add("X-Content-Type-Options valor incomum: -3");
                }
            }

            // --- CSP ---
            if (header.equalsIgnoreCase("Content-Security-Policy")) {
                if (status.startsWith("MISSING")) {
                    score -= 10;
                    notes.add("Content-Security-Policy ausente: -10");

                    issues.add(new SecurityIssue(
                            "CSP_MISSING",
                            "Content-Security-Policy ausente",
                            "HIGH",
                            "Aumenta o risco de XSS e injeção de conteúdo.",
                            "Adicionar header CSP (início simples): Content-Security-Policy: default-src 'self'"
                    ));
                } else if (status.startsWith("WEAK")) {
                    score -= 5;
                    notes.add("Content-Security-Policy fraca: -5");

                    issues.add(new SecurityIssue(
                            "CSP_WEAK",
                            "Content-Security-Policy fraca",
                            "MEDIUM",
                            "Política permissiva pode não impedir XSS/injeções.",
                            "Revisar CSP para restringir fontes e evitar 'unsafe-inline' quando possível."
                    ));
                } else if (status.startsWith("UNKNOWN")) {
                    score -= 3;
                    notes.add("CSP valor incomum: -3");
                }
            }

            // --- X-Frame-Options ---
            if (header.equalsIgnoreCase("X-Frame-Options")) {
                if (status.startsWith("MISSING")) {
                    score -= 10;
                    notes.add("X-Frame-Options ausente: -10");

                    issues.add(new SecurityIssue(
                            "XFO_MISSING",
                            "X-Frame-Options ausente",
                            "MEDIUM",
                            "Aumenta risco de clickjacking em browsers que ainda dependem desse header.",
                            "Adicionar X-Frame-Options: DENY (ou SAMEORIGIN se precisar de iframe)."
                    ));
                } else if (status.startsWith("WEAK")) {
                    score -= 5;
                    notes.add("X-Frame-Options fraco: -5");

                    issues.add(new SecurityIssue(
                            "CLICKJACKING_RISK",
                            "Proteção contra clickjacking fraca",
                            "MEDIUM",
                            "Página pode ser embutida em iframe em alguns contextos.",
                            "Preferir X-Frame-Options: DENY se o site não precisa ser exibido em iframe."
                    ));
                } else if (status.startsWith("UNKNOWN")) {
                    score -= 3;
                    notes.add("X-Frame-Options valor incomum: -3");
                }

            }
        }

        // ===== LIMITAR SCORE =====
        if (score < 0) score = 0;
        if (score > 100) score = 100;

        RiskLevel level = classify(score);

        return new ScoreResult(score, level, notes, issues);
    }

    private RiskLevel classify(int score) {
        if (score >= 80) return RiskLevel.SECURE;
        if (score >= 50) return RiskLevel.WARNING;
        return RiskLevel.CRITICAL;
    }
}