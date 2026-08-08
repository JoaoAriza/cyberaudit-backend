# CyberAudit — Backend

API de **auditoria de segurança de sites**. A partir de uma URL, avalia a postura de
segurança do alvo (TLS, headers, DNS/e-mail, exposições, vulnerabilidades comuns) e
produz uma **nota de 0 a 100** com nível de risco, lista de issues acionáveis e
relatórios (texto / PDF).

> Spring Boot 3.5.16 · Java 17 · PostgreSQL. Faz par com o frontend `cyberaudit-ui` (React).

> ⚠ **Antes de publicar**, leia [`docs/DEPLOY_CHECKLIST.md`](docs/DEPLOY_CHECKLIST.md) —
> há variáveis de ambiente sem as quais a aplicação não sobe ou sobe com um controle
> de segurança desligado. O histórico da revisão de segurança está em
> [`docs/SECURITY_REVIEW_SCOPE.md`](docs/SECURITY_REVIEW_SCOPE.md).

---

## Índice
- [Visão geral](#visão-geral)
- [Stack](#stack)
- [Como o scan funciona](#como-o-scan-funciona)
- [Módulos de verificação](#módulos-de-verificação)
- [Modelo de pontuação](#modelo-de-pontuação)
- [Segurança e prevenção de abuso](#segurança-e-prevenção-de-abuso)
- [Honestidade do resultado (anti-falso-positivo)](#honestidade-do-resultado-anti-falso-positivo)
- [APIs externas (todas gratuitas)](#apis-externas-todas-gratuitas)
- [Configuração](#configuração)
- [Como rodar localmente](#como-rodar-localmente)
- [Principais endpoints](#principais-endpoints)
- [Estrutura de pacotes](#estrutura-de-pacotes)
- [Limitações conhecidas / trabalho futuro](#limitações-conhecidas--trabalho-futuro)

---

## Visão geral

Dois modos de scan:

- **Passivo** (padrão, aberto a visitantes com rate-limit): só observa — TLS, headers,
  DNS, fingerprint, CT logs, etc. Não envia payloads ao alvo.
- **Ativo** (requer autenticação **e** prova de propriedade do domínio): além do passivo,
  envia probes (CORS, arquivos sensíveis, open redirect, XSS/SQLi/SSRF/LFI/CRLF quando há
  superfície de input, port scan, WAF). Só deve ser usado em domínios autorizados.

O resultado é um `ScanResult` com a nota, o nível de risco, as issues, o detalhamento por
módulo e o **status de cada verificação** (OK / TIMEOUT / SKIPPED).

---

## Stack

| Camada | Tecnologia |
|---|---|
| Runtime | Java 17, Spring Boot 3.5.16 |
| Web | spring-boot-starter-web |
| Persistência | spring-data-jpa + Hibernate, PostgreSQL |
| Segurança | spring-security + JWT (jjwt), API keys, 2FA TOTP (dev.samstevens.totp) |
| DNS | dnsjava 3.5 |
| PDF | Apache PDFBox 2.0 |
| Cache | Caffeine |
| Rate limit | Bucket4j |
| E-mail | spring-boot-starter-mail (SMTP) |
| Boilerplate | Lombok |

---

## Como o scan funciona

Tudo entra por `ScanController` → `ScanOrchestrator.execute()`, que é o **funil único**
(scan síncrono, assíncrono e agendado passam por ele). Fases:

```
execute(url, active, user)
  │
  ├─ normalizeUrl + SsrfGuard.validate   ← bloqueia alvos internos antes de qualquer request
  │
  ├─ FASE 1 (sequencial): SSL → TLS → redirect HTTP→HTTPS → fetch de headers (GET)
  │
  ├─ FASE 2 (passivo, paralelo, ~14 módulos): robots, security.txt, DNS, métodos HTTP,
  │     directory listing, takeover, source maps, host header, API docs, GraphQL,
  │     cert transparency, fingerprint+CVE, hosts relacionados
  │
  ├─ FASE 3: ownership check (só scan ativo) — exige propriedade verificada ou role OWNER/ADMIN
  │
  ├─ FASE 4 (ativo, paralelo, ~10 módulos): CORS, arquivos sensíveis, WAF, open redirect,
  │     XSS, SQL error, port scan, path traversal, SSRF, CRLF
  │
  └─ ScoreService.calculate() → ScanResult (+ compliance, + change detection, + cache, + histórico)
```

Cada módulo roda em pool paralelo com timeout. Se um não conclui no orçamento da fase, é
marcado **TIMEOUT** (não confundido com "verificado e sem achado").

---

## Módulos de verificação

> Cada item é um `*Service` em `com.joao.cyberaudit.service`.

**Transporte / TLS**
- `SSLService` — HTTPS, validade e expiração do certificado.
- `TlsVersionService` — protocolo TLS negociado (sinaliza TLS 1.0/1.1 deprecated).

**Headers / Cookies**
- `HttpFetchService` — fetch base (GET, segue redirects; lê **CSP via `<meta http-equiv>`** quando não vem no header).
- `HeaderService` — 6 headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
- `CookieSecurityService` — flags Secure / HttpOnly / SameSite.
- `JwtSecurityService` — analisa JWTs presentes em cookies/headers (passivo: `alg:none`, sem `exp`, alg fraco).

**DNS / e-mail**
- `DnsSecurityService` — SPF, DMARC, DKIM, MX, CAA → risco de e-mail spoofing. Usa o **apex registrável** (Public Suffix List) no fallback.
- `PublicSuffixService` — resolve eTLD+1 a partir da PSL (`resources/public_suffix_list.dat`).
- `CertTransparencyService` + `CrtShService` — subdomínios via CT logs (crt.sh, compartilhado).

**Reconhecimento**
- `TechFingerprintService` — servidor, framework, CMS, libs e versões detectadas.
- `CVECorrelationService` — CVEs via **NVD** por CPE (marcados como *potenciais* — baseados na versão do banner).
- `SubdomainTakeoverService` — CNAME apontando para serviço não reivindicado.
- `SourceMapService` — source maps `.map`, Spring Actuator e debug endpoints (com markers específicos).
- `RelatedHostsHeaderService` — headers de hosts relacionados (`api.`, `server.`, `www.`…) — **informativo**, não entra no score.

**Aplicação — passivo**
- `HttpMethodService` — métodos perigosos (TRACE/PUT/DELETE/CONNECT).
- `DirectoryListingService` — listagem de diretório habilitada.
- `ApiDocsExposureService` — Swagger/OpenAPI/ReDoc expostos.
- `GraphQlIntrospectionService` — introspection / playground públicos.
- `RobotsTxtService` — paths sensíveis em robots.txt.
- `SecurityTxtService` — presença de `/.well-known/security.txt`.
- `HostHeaderService` — Host Header Injection (reflexão em Location/Set-Cookie = explorável; body = informativo).

**Aplicação — ativo** (autenticado + ownership)
- `CorsAnalyzerService` — CORS mal configurado (reflection, wildcard+credentials, null origin).
- `SensitiveFileService` — `.env`, `.git`, backups, `wp-config`, actuator, etc. (com validação de conteúdo).
- `WafDetectionService` — detecção de WAF por header e por **bloqueio diferencial** de payload.
- `OpenRedirectService` — open redirect em parâmetros.
- `XssProbeService` — reflected XSS (heurístico, marcado como *suspeita*).
- `ErrorDisclosureService` — vazamento de erro de banco (SQLi).
- `PathTraversalService` — LFI / path traversal.
- `SsrfService` — SSRF (metadata cloud, internos).
- `CrlfService` — CRLF injection.
- `PortScanService` — portas comuns (DB/SSH/FTP/SMTP…), com confirmação por banner.

**Pontuação, relatórios e suporte**
- `ScoreService` — agrega tudo em 0–100 + nível de risco + issues.
- `ReportService` (texto), `PdfReportService`, `ExecutivePdfReportService`.
- `ComplianceMappingService` — mapeia achados para LGPD / ISO 27001.
- `ScanChangeDetector` + `ScanHistoryService` — diff entre scans e histórico.
- `ScanOrchestrator`, `AsyncScanService`, `ScanCacheService` (Caffeine).
- `SsrfGuard`, `DomainProtectionService`, `RateLimitService`, `GuestRateLimitService`, `PlanLimitService`.
- Auth: `AuthService`, `JwtUtil`/`JwtAuthFilter`, `ApiKeyService`/`ApiKeyAuthFilter`, `TotpService`/`TwoFactorService`.
- `ScheduledScanService` (cron), `EmailService`, `AuditService`, `DataExportService`/`DataRetentionService` (LGPD), `BadgeService`, `InviteService`.

---

## Modelo de pontuação

Começa em **100** e aplica penalidades/bônus por achado. Faixas de risco:

| Nota | Nível |
|---|---|
| ≥ 85 | SECURE |
| ≥ 70 | LOW |
| ≥ 45 | MEDIUM |
| ≥ 20 | HIGH |
| < 20 | CRITICAL |

**Severity override:** uma issue `HIGH` força o risco para no mínimo MEDIUM, e uma
`CRITICAL` para no mínimo HIGH — independente da nota numérica. Assim um achado sério não
se esconde atrás de uma nota boa (ex: site 83 com risco de e-mail spoofing HIGH → MEDIUM).

**Resultado parcial:** `ScanResult.moduleStatus` registra cada módulo como `OK`,
`TIMEOUT` ou `SKIPPED`. Quando há módulos não concluídos, o relatório marca explicitamente
"resultado parcial" — ausência de achado num módulo que não rodou **não** significa
ausência de risco. (O score não é penalizado pela falha de coleta, só sinalizado.)

---

## Segurança e prevenção de abuso

- **Anti-SSRF (`SsrfGuard`)** — toda URL de scan é validada antes de qualquer requisição;
  bloqueia loopback, link-local (inclui metadata cloud `169.254.169.254`), redes privadas
  RFC 1918, CGNAT e ULA IPv6. Evita que o backend seja usado como proxy de SSRF / port-scanner.
- **Scan ativo gated** — exige autenticação **e** verificação de propriedade do domínio
  (`DomainProtectionService`, arquivo `/.well-known/cyberaudit.txt`) ou role OWNER/ADMIN.
- **Rate limiting** — por IP (visitante) e por usuário; limite diário de scans para guests;
  limites por plano (`PlanLimitService`).
- **Autenticação** — JWT, API keys, 2FA TOTP, roles (OWNER/ADMIN/…).
- **Header `Host` restrito** liberado no `main()` (`jdk.httpclient.allowRestrictedHeaders=host`)
  para o probe de Host Header Injection funcionar.

---

## Honestidade do resultado (anti-falso-positivo)

Decisões deliberadas para o relatório não mentir nem assustar à toa:

- **CSP via `<meta>`** lida do HTML (SPAs entregam CSP assim) → fim do "CSP MISSING" falso.
- **Apex via Public Suffix List** em SPF/MX/DKIM → fim do "sem SPF = CRITICAL" ao escanear `www.`.
- **CVE como *potencial*** — correlação por versão de banner pode ser falso positivo por backport; severidade rebaixada e rotulada.
- **WAF por bloqueio diferencial** — 403 só conta se for específico do payload (benigno passa).
- **Host header no body = informativo (LOW)** — reflexão em canonical/og:url é comum e benigna.
- **Debug endpoints exigem markers** da ferramenta (SPA 200 + index.html não dispara mais).
- **Erro de fetch penaliza** "headers não verificados" (antes inflava a nota).
- **`analyzedHost`** — o resultado diz de qual host os headers vieram (evita confundir com subdomínio de API).

---

## APIs externas (todas gratuitas)

Nenhuma API paga embutida. O custo de operação é **infraestrutura**, não API.

| Serviço | Uso | Custo |
|---|---|---|
| NVD (nist.gov) | Correlação de CVE | Grátis (rate-limit; chave grátis aumenta) |
| crt.sh | Certificate Transparency / subdomínios | Grátis |
| DNS | SPF/DMARC/DKIM/MX, takeover | Grátis (rede do servidor) |
| Public Suffix List | Resolução de apex | Grátis (embutida como resource) |

---

## Configuração

Variáveis de ambiente (ver `src/main/resources/application.properties`):

| Variável | Default | Descrição |
|---|---|---|
| `DB_URL` | `jdbc:postgresql://localhost:5434/cyberaudit` | URL do Postgres |
| `DB_USERNAME` / `DB_PASSWORD` | `cyberaudit` / `cyberaudit123` | Credenciais do banco |
| `JWT_SECRET` | *(obrigatório)* | Segredo de assinatura JWT — gere com `openssl rand -base64 48` |
| `ALLOWED_ORIGINS` | `http://localhost:5173,http://localhost:3000` | Origens CORS permitidas (frontend) |
| `MAIL_ENABLED` | `false` | Liga/desliga envio de e-mail |
| `MAIL_HOST`/`MAIL_PORT`/`MAIL_USERNAME`/`MAIL_PASSWORD`/`MAIL_FROM` | SMTP | Config de e-mail |
| `server.port` | `8081` | Porta HTTP |

> `spring.jpa.hibernate.ddl-auto=update` — o schema é criado/atualizado automaticamente.

---

## Como rodar localmente

```bash
# 1) Copie o .env.example para .env e preencha (DB_PASSWORD e JWT_SECRET são obrigatórios)
cp .env.example .env

# 2) Postgres — o compose lê DB_PASSWORD do .env e publica só em 127.0.0.1
docker compose up -d

# 3) Rodar
mvn spring-boot:run
```

API em `http://localhost:8081`. O frontend (`cyberaudit-ui`) sobe em `:5173` e aponta para cá via `VITE_API_URL`.

```bash
mvn clean package      # gera o jar executável em target/
mvn -q -o compile      # apenas compila
mvn test               # suíte de testes
```

### Rodar em container

A imagem já roda como usuário não-root (uid 10001) e com o jar somente-leitura.
Em produção, complete o isolamento no `docker run` — verificado funcionando com
todas estas flags:

```bash
docker run -d --name cyberaudit \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop ALL --security-opt no-new-privileges \
  --env-file .env -p 8081:8081 \
  cyberaudit
```

`--read-only` funciona porque o app não escreve em disco (o PDF é gerado em
memória); o `tmpfs` em `/tmp` existe só para arquivos temporários da JVM.

> **Nunca** use `--env-file` apontando para um `.env` versionado, nem embuta
> segredos com `ENV` no Dockerfile — o valor fica na imagem e no histórico dela.

---

## Principais endpoints

> Visão de alto nível — ver os `*Controller` para detalhes.

| Área | Controller | Exemplos |
|---|---|---|
| Scan | `ScanController` | `GET /scan?url=…&active=` · `POST /scan/async` · `GET /scan/report` · `GET /scan/report/pdf/{scanId}` · `GET /scan/verify-token` |
| Auth | `AuthController` | login, registro, setup do owner, 2FA |
| Admin | `AdminController` | gestão administrativa |
| Domínios | `DomainController` | domínios da conta / verificação |
| Histórico | `HistoryController` | scans anteriores, diffs |
| Agendamentos | `ScheduledScanController` | scans recorrentes (cron) |
| API keys | `ApiKeyController` | chaves de API |
| Badge | `BadgeController` | `GET /badge/{host}` (SVG) |
| Status público | `PublicStatusController` | status público |
| Conta / Usuários | `AccountController`, `UserController` | conta, membros, convites |
| Health | Spring Actuator | `GET /actuator/health` |

---

## Estrutura de pacotes

```
com.joao.cyberaudit
├── controller   endpoints REST
├── service      orquestração + ~50 serviços (módulos de scan, score, relatórios, auth…)
├── model        entidades JPA e DTOs de resultado (ScanResult, ScoreResult, *Finding…)
├── dto          DTOs de request/response
├── repository   Spring Data repositories
├── security     JWT, API key filters, UserDetails
├── config       Security, CORS, headers, JWT properties
├── exception    exceções de domínio + GlobalExceptionHandler
└── util         utilitários (ex: CnpjUtil)
```

---

## Limitações conhecidas / trabalho futuro

- **Sem crawler.** Os probes de injeção (XSS, SQLi, SSRF, LFI, CRLF em parâmetro) só
  rodam quando a URL tem superfície de input (`?param=…`). Escanear só a home raramente
  exercita esses módulos — o relatório deixa isso explícito (SKIPPED), mas adicionar um
  crawler leve aumentaria muito a cobertura.
- **SSRF / DNS-rebinding.** O `SsrfGuard` bloqueia o alvo direto interno, mas não fixa o IP
  na conexão — fechar o rebinding (TOCTOU) exige pinning do IP resolvido no fetch.
- **PSL é um snapshot.** `public_suffix_list.dat` tem data de versão; precisa de refresh
  periódico (re-baixar de publicsuffix.org).
- **Port scan atrás de CDN.** Resolve o IP do edge (Cloudflare/Vercel), não a origem.
- **`ddl-auto=update`** é prático para esta escala, mas para produção séria o ideal seria
  migrations versionadas (Flyway/Liquibase).
