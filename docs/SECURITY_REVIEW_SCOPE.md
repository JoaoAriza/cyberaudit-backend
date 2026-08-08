# 🛡️ Escopo de Revisão de Segurança — CyberAudit (pré-lançamento)

> Documento de escopo para auditar a segurança do próprio CyberAudit antes de ir pra web.
> Feito pra ser trabalhado **categoria por categoria** num chat novo. Marque `[x]` conforme verifica.
>
> **Status: P0, P1, P2 e P3 fechados no código** (3 rodadas, 2026-08-03 a 06). O que
> sobrou depende do ambiente de produção e está consolidado em
> [`DEPLOY_CHECKLIST.md`](DEPLOY_CHECKLIST.md) — leia aquele antes de subir.
>
> **Stack:** Spring Boot 3.2.5 / Java 17 / PostgreSQL / React 19 + Vite / Docker / Mercado Pago.
> **Localização:** Backend `C:\Projetos\Cyberaudit\Backend`, Frontend `C:\Projetos\Cyberaudit\Frontend`.
> Este documento cobre os **dois** repositórios, mas vive no do backend para ficar
> versionado (antes estava em `Cyberaudit\Docs\`, fora de qualquer git).
> **Ferramentas úteis no chat novo:** `/security-review` (revisa o diff/código), rodar o próprio CyberAudit contra a instância publicada (dogfooding), scanner externo, `npm audit`, OWASP dependency-check.

---

## 🎯 Prioridade 0 — O MOTOR DE SCAN (risco único deste produto)

O app faz **requisições de saída para URLs que o usuário fornece** → é a maior superfície de ataque. Um scanner mal protegido vira ferramenta de ataque.

- [x] **SSRF** — `SsrfGuard` reescrito: RFC1918, loopback, link-local/metadata, `0.0.0.0`, CGNAT, faixas reservadas IANA (192.0.0/24, 198.18/15, TEST-NET, 240/4), ULA IPv6 e **IPv4 embutido em IPv6** (mapped, NAT64, 6to4). Também rejeita userinfo na URL (`https://alvo@169.254.169.254/`) e nomes de rede interna (`*.local`, `*.internal`). 44 testes.
- [x] **DNS rebinding** — mitigado (não eliminado): `pinDnsCache()` no boot fixa `networkaddress.cache.ttl=30`, então a resolução da validação e a da conexão vêm da mesma entrada de cache. Fechar de vez exigiria conectar no IP validado com SNI/Host preservados — inviável no `HttpClient` do JDK 17.
- [x] **Redirects** — `ScannerHttp.sendFollowingSafely()` segue manualmente revalidando cada hop no `SsrfGuard`, máx. 5 hops. Os 11 clientes que usavam `Redirect.ALWAYS/NORMAL` passaram para `NEVER`. Headers atrelados à origem (`Host`, `Authorization`, `Cookie`, `Origin`) não atravessam hop.
- [x] **Esquemas** — allowlist `http`/`https` no `SsrfGuard.validate()`; `file://`, `gopher://`, `dict://`, `jar:`, `ftp://` e URL sem esquema são rejeitados.
- [x] **Exaustão de recursos** — `ScannerHttp.limitedString()` (3 MiB, 16 MiB para JSON de API externa) substitui todos os `BodyHandlers.ofString()`: para de ler e cancela a assinatura no teto. Timeouts de conexão/leitura já existiam; o tempo total por scan segue limitado pelos `get(120s)` de cada fase.
- [x] **Limite global de scans concorrentes** — `ScanConcurrencyLimiter` (semáforo justo, `scan.max-concurrent`, default 4). Fila com timeout de 20s e 503 `SCAN_CAPACITY` no estouro. Cache hit não ocupa slot.
- [x] **Scan ativo** — exige auth em TODOS os endpoints de scan (era burlável via `/scan/report`). Prova de posse corrigida: o token virou HMAC-SHA256(segredo do servidor, host) e a verificação passou a exigir **igualdade exata** — antes qualquer conteúdo começando com `cyberaudit-verify=` liberava scan ativo.
- [x] **Injeção nos probes** — payloads auditados: todos são constantes fixas, nenhum é controlável pelo usuário, e nenhum faz o alvo (ou nós) mandar tráfego para terceiros. O probe de open redirect nunca conecta no domínio de probe (`Redirect.NEVER` + `discarding()`); o de SSRF só aponta para loopback/metadata do próprio alvo; o de CRLF e o de Host Header injetam header fixo e inócuo. `PortScanService` — único a resolver DNS por conta própria e abrir socket cru — agora confere o IP resolvido no `SsrfGuard` antes de conectar.
  - **O risco real não era o payload, era o ALVO**: conta EMPRESA passava direto em `checkActiveScan` (qualquer domínio), e a heurística `requiresOwnershipForActiveScan` era invertida — dispensava a prova de posse justamente quando o alvo parecia BEM configurado. Juntos: port scan + probes de CRLF/open-redirect/arquivos sensíveis contra terceiros a partir do IP do CyberAudit. **Posse agora é exigida sempre** (heurística removida, EMPRESA sem exceção).

---

## 🔐 Prioridade 1 — Autenticação & Sessão

- [ ] **JWT_SECRET** forte (32+ chars — já ajustado) e **fora do git** (`.env` gitignored ✓). Rotacionar em produção. *(⚠ ver nota da Rodada 2 — rotacionar invalida os tokens de posse de domínio)*
- [x] **Algoritmo JWT** — JJWT 0.12 com `verifyWith(SecretKey).parseSignedClaims()`: rejeita `alg:none` (exige JWS assinado), rejeita confusão HS/RS (só chave MAC configurada) e valida `exp` sempre. Alg derivado do tamanho da chave (HS256/384/512), não fixo — sem problema de segurança.
- [ ] **Token no `localStorage`** (frontend) → vulnerável a roubo via XSS. Considerar cookie `HttpOnly`+`Secure`+`SameSite` pra o token. (trade-off — avaliar.)
- [x] **Hash de senha** — BCrypt custo 12 para senhas (era o default 10); nenhuma senha em log. API keys ganharam encoder próprio (custo 10, `@Qualifier("apiKeyEncoder")`): o hash é verificado a cada request de CI/CD e custo 12 poria ~250 ms de CPU em cada chamada — derivação lenta não compra nada contra token aleatório de alta entropia. **Política mínima de senha** (`PasswordPolicy`, 8–128 chars) passou a valer no `setup` e no aceite de convite, que aceitavam qualquer coisa — inclusive senha de 1 caractere, justamente nas contas OWNER.
- [x] **2FA (TOTP + OTP e-mail)** — OTP expira em 10 min ✓, uso único ✓. **Faltava rate-limit**: `AuthThrottleService` trava após 5 tentativas por 15 min e o reenvio de OTP tem cooldown de 60 s (o endpoint aceita token pre-auth — era bomba de e-mail). `totpSecret` segue em texto no banco — *pendente*, considerar criptografia em repouso.
- [x] **Brute-force no login** — não havia bloqueio nenhum: `LOGIN_FAILED` ia pro audit e a tentativa seguinte passava. Agora lockout de 15 min após 5 falhas por conta e 20 por IP, zerado em qualquer sucesso.
- [x] **Token pré-2FA** — **era um bypass completo de 2FA.** O filtro liberava `/auth/2fa/**` inteiro, o que inclui `DELETE /auth/2fa/totp` e `DELETE /auth/2fa/email`: quem tivesse só a senha desativava o 2FA da vítima e entrava sem segundo fator. Além disso o `startsWith` comparava `getRequestURI()` cru, então `/auth/2fa/../../admin/users` passava e era roteado para `/admin`. Agora: allowlist por igualdade exata (só `verify` e `send-email-otp`), caminho normalizado, e o token pre-auth recebe apenas `ROLE_PRE_AUTH` em vez das authorities reais.
- [x] **Convites/invites** — 48h ✓, uso único (`accepted`) ✓, token `UUID.randomUUID()` (122 bits) ✓. **Mas `/admin/invites` listava os convites pendentes de TODAS as contas, com o link de aceite incluso** — qualquer OWNER entrava na empresa alheia. Escopado por conta; `revoke` também.

---

## 🚪 Prioridade 1 — Autorização & Isolamento Multi-tenant

- [x] **Checagem de role** em TODO endpoint sensível — **o modelo de role estava quebrado na raiz**: `/auth/register` é público e cria todo cadastro já como `Role.OWNER`. Como `requireOwner()` só olhava o role, bastava se registrar para virar "OWNER" e, com isso, (a) `GET /admin/users` devolvia `findAll()` — nome, e-mail e role de TODOS os clientes; (b) alterar role, desativar e reativar usuário de qualquer conta pelo UUID; (c) pular a prova de posse de domínio no scan ativo, anulando o controle do P0. Corrigido: `/admin/**` escopado pela conta do chamador, e o privilégio cross-tenant saiu do role para uma lista explícita de configuração (`PlatformStaffService` / `PLATFORM_STAFF_EMAILS`, **vazia por padrão**).
- [~] **Isolamento entre contas (IDOR)** — usuário de uma conta NÃO acessa scans/domínios/feedback/api-keys/assinatura/usuários de outra. Testar cada endpoint que recebe id (`scanId`, `domainId`, `feedbackId`, `userId`, `subscriptionId`) com id de outra conta.
  - O feedback já é escopado por conta (`FeedbackService`), a assinatura idem.
  - **CORRIGIDO — histórico**: `/history/recent`, `/history/{host}` e `/history/{id}/result` não filtravam por conta: qualquer usuário logado lia os scans de *todas* as contas, e `/{id}/result` devolvia o `ScanResult` completo sem gating de plano. Agora tudo passa por `Account` no repositório e o resultado sai com `applyEntitlement`. Scan de outra conta → 404.
  - **CORRIGIDO — scan async**: `/scan/async/{scanId}` (público) e `/scan/report/pdf/{scanId}` não checavam dono. Agora o scanId é amarrado a quem submeteu (e-mail para autenticado, IP para guest) e o `statusMap`, que crescia sem limite, tem TTL de 1h + teto de 5k entradas.
  - **Domínios e API keys**: auditados, já estavam corretos — `DomainService.getOwned()` e `ApiKeyService.revoke()` comparam a conta antes de agir. `/user/**` opera só sobre o próprio usuário (sem id em path).
  - **CORRIGIDO — usuários e convites**: `/admin/users*` e `/admin/invites` eram cross-tenant (ver "Checagem de role" acima).
- [ ] **Gating de plano** — 100% server-side (`ScanEntitlementService`, não-destrutivo/cache-safe ✓). Confirmar que impacto/correção/módulos travados NÃO vazam no payload pra guest/FREE.
- [ ] **API keys** — escopo correto, revogação funciona, rate-limit próprio, não expõem dados de outra conta.

---

## 💉 Prioridade 1 — Validação de Entrada & Injeção

- [x] **SQL Injection** — auditado: zero `nativeQuery = true`, zero `createQuery`/`createNativeQuery`, zero concatenação de string em query. Só JPQL com `@Param` e derived queries.
- [x] **XSS** — zero `dangerouslySetInnerHTML` em todo o `Frontend/src` ✓. Templates do `EmailService` auditados na Rodada 3 (ver Etapa 8): `escHtml` existia mas **não cobria todas as interpolações** e não escapava aspas. **Templates HTML do `EmailService`** — confirmar que TODO input de usuário passa por `escHtml()` (host, nome, mensagem de feedback, etc.).
- [ ] **Command injection** — o scanner faz shell-out pra alguma ferramenta externa? Se sim, sanitizar argumentos.
- [ ] **Path traversal** — geração de relatório, logo da marca (base64), qualquer manuseio de arquivo/path.
- [x] **Deserialização** — auditado: nenhum `activateDefaultTyping`/`enableDefaultTyping` no projeto. `ScanResult` desserializa com typing estático.
- [x] **Validação de tamanho** — feedback com cap de 4000 ✓. **Logo**: o limite era só o comprimento da string base64, sem checar formato nem dimensões → `BrandLogoValidator` (assinatura PNG/JPEG, bytes decodificados, dimensões e pixels totais lidos do cabeçalho). **Campos de registro**: `name`/`email` não tinham teto e estouravam na coluna `varchar(255)` como erro 500 — agora 400 claro (120 / 254 chars). `brandReportName` também ganhou cap (120).

---

## 🔑 Prioridade 2 — Segredos & Configuração

- [~] Segredos NUNCA no git — histórico completo dos dois repos varrido (144 commits no backend).
  - 🔴 **`JWT_SECRET` REAL VAZADO NO HISTÓRICO PÚBLICO**: `jwt.secret=${JWT_SECRET:31082005@JoaoAriza-cyberaudit-chave-segura!!}` está nos commits `7edf6a4` e `65e0e0f`, já em `origin/main` de `github.com/JoaoAriza/cyberaudit-backend` — **repositório público**. O `.env` local usa outro valor, então não é o segredo em uso, mas a string está queimada e revela um padrão pessoal de senha (data de nascimento + nome). **Ação pendente do dono do repo** — ver Rodada 3 abaixo.
  - Nenhum token de MP/Gmail/NVD/GitHub encontrado no histórico ✓.
  - `Frontend/.env` estava **rastreado** (o `.gitignore` só vale para arquivo ainda não versionado). Conteúdo era inócuo (`VITE_API_URL=http://localhost:8081`), mas era um acidente esperando acontecer — removido do índice, `.env.example` criado.
- [x] **Produção**: `spring.datasource.password` perdeu o default `cyberaudit123` — deploy sem `DB_PASSWORD` agora falha no boot em vez de subir com senha de exemplo pública. `docker-compose.yml` também não tem mais senha hardcoded (lê do `.env`). Variáveis novas documentadas no `.env.example`: `DOMAIN_VERIFICATION_SECRET`, `PLATFORM_STAFF_EMAILS`, `FORWARD_HEADERS`, `SCAN_MAX_CONCURRENT`, `SCAN_ACQUIRE_TIMEOUT`, `DNS_CACHE_TTL_SECONDS`.
- [ ] Segredos via env var / secret manager no deploy (não `.env` em disco no servidor).
- [x] Sem segredo em log, mensagem de erro ou resposta de API — nenhum `println`/log de senha, token ou chave.
- [x] **`GlobalExceptionHandler`** — `server.error.include-stacktrace/message/exception/binding-errors=never` explícitos. O `AsyncScanService` devolvia `e.getMessage()` cru no status do scan (qualquer exceção interna ia pro cliente); agora só passam mensagens de negócio e falhas de rede categorizadas.

---

## 💳 Prioridade 2 — Billing (Mercado Pago)

- [x] **Webhook** (`POST /billing/webhook`, público) — confirma o status na API do MP antes do upgrade ✓ (não confia no corpo). **Mas a validação de `x-signature` era simplesmente PULADA quando `MP_WEBHOOK_SECRET` estava vazio** — inclusive em produção, onde esquecer a variável deixava o endpoint aberto para qualquer um mandar notificação. Agora só pula quando o MP não está integrado de fato (sem `MP_ACCESS_TOKEN`, isto é, dev/sandbox sem dinheiro envolvido); com o MP ativo e sem secret, **rejeita e loga**. Comparação do HMAC passou a ser em tempo constante (`MessageDigest.isEqual`).
- [x] **Idempotência** — verificada por teste: o handler relê o status atual na API do MP e reaplica o mesmo estado, então webhook duplicado (ou fora de ordem) converge para o estado real, sem upgrade duplo.
- [x] **Sem manipulação de preço** pelo cliente — valor vem da config do servidor na criação ✓. Adicionada checagem no outro lado: o upgrade só ocorre se o `auto_recurring.transaction_amount` que o MP devolve cobrir o preço configurado do plano. Valor ausente na resposta não bloqueia (a API do MP nem sempre devolve `auto_recurring`, e travar aí deixaria cliente pagante sem acesso).
- [x] Rate-limit no webhook — 60/min por IP (era ilimitado, e cada notificação aceita dispara uma chamada à API do MP: flood na nossa cota). **IDOR: não se aplica** — `subscribe`/`subscription`/`cancel` derivam a conta de `@AuthenticationPrincipal`, nenhum id vem do cliente.
- 8 testes novos cobrindo o caminho do dinheiro (`BillingServiceTest`).

---

## 🌐 Prioridade 2 — Transporte, Headers & "Coma sua própria ração"

- [ ] **HTTPS everywhere** em produção (Let's Encrypt). HSTS ligado.
- [ ] **RODE O CYBERAUDIT CONTRA ELE MESMO** (dogfooding) — checar seus próprios: security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy), config TLS, flags de cookie, source maps expostos, docs de API expostas. Resolve a ironia. 🎯
- [x] **CORS** — trocado `allowedOriginPatterns` (aceita curinga silenciosamente) por `allowedOrigins` (comparação exata), e o boot **falha** se `ALLOWED_ORIGINS` vier vazio ou com `*`. `allowedHeaders("*")`/`exposedHeaders("*")` viraram listas explícitas. `allowCredentials` segue `false` (auth é Bearer, não cookie).
- [x] **CSP** — ⚠️ **a afirmação deste doc estava errada: o frontend não tinha CSP nenhuma.** Nem `<meta>` no `index.html`, nem arquivo de config de host. Com o JWT no `localStorage`, qualquer XSS levava a sessão. Agora: CSP injetada no `index.html` **no build** (`vite.config.ts`, `apply: 'build'` — em dev quebraria o preamble do React Refresh), com `script-src 'self'` viabilizado pela extração do script de tema inline para `public/theme-init.js`. `frame-ancestors` e HSTS não funcionam em `<meta>`, então vão como header real em `vercel.json` e `public/_headers` (Netlify/Cloudflare Pages); README cobre nginx/Caddy.
- [x] Cookies — **não se aplica**: a API não emite `Set-Cookie` (sessão é `STATELESS`, auth por Bearer).
- [x] Headers da API — faltavam `Referrer-Policy` e `Permissions-Policy` (ambos adicionados) e a CSP era só `default-src 'self'`, que não cobre `frame-ancestors`/`base-uri`/`form-action`/`object-src`. Como é API pura, a CSP virou `default-src 'none'` + `sandbox`: uma resposta aberta direto no navegador não executa nada. Adicionado `Cache-Control: no-store` em tudo menos `/badge/` — sem isso, cache compartilhado poderia servir resposta de uma conta para outra (a mesma URL devolve conteúdo diferente por plano).

---

## 🚦 Prioridade 2 — Rate Limiting, Abuso & DoS

- [x] Rate-limit de guest (5/dia por IP, `GuestRateLimitService`) e limites diários por plano — **`/scan/report` não tinha NENHUM** (guest fazia scan ativo anônimo e ilimitado por ali) e `/scan/report/pdf` não consumia cota diária. Unificado em `ScanController.enforceScanLimits()`, aplicado nos 4 endpoints.
  - ⚠ **Atenção no deploy**: atrás de proxy reverso, `getRemoteAddr()` devolve o IP do proxy e todos os guests caem no mesmo balde. Setar `FORWARD_HEADERS=framework` em produção (property já adicionada, default `none`).
- [x] `RateLimitService` (RPM) aplicado nos pontos certos — faltava no `/scan/verify-check` (público, gera requisição de saída). Adicionado.
- [x] **Limite global de scans concorrentes** (repetido da P0 — DoS).
- [x] Geração de PDF com limite de recurso — a entrada não-limitada era o **logo da marca**: o cap existente media só o tamanho da string base64, o que deixa passar bomba de descompressão. Ver `BrandLogoValidator` na Etapa 4.
- [x] Brute-force de login/OTP (repetido da P1).

---

## 📋 Prioridade 3 — Proteção de Dados / LGPD

- [~] PII (e-mail, nome, CNPJ) — controle de acesso verificado (tudo escopado por conta após as rodadas 1–2). **Pendente**: criptografia em repouso para campos sensíveis, incluindo o `totpSecret`, que segue em texto no banco.
- [x] **Export / exclusão de dados** (LGPD) — export verificado: devolve só os dados do próprio usuário, sem `passwordHash` nem `totpSecret`. **A exclusão estava quebrada** — ver Etapa 7 abaixo.
- [x] **Audit logs** — `GET /admin/audit-logs` exige OWNER/ADMIN e é escopado por `accountId`; **não existe endpoint de exclusão**, então nem admin apaga rastro pela API (só a rotina de retenção). Não guardam senha nem token. ⚠ `SCAN_STARTED` registra a URL completa do alvo: se o usuário escanear uma URL com credencial na query string, ela fica no log.
- [~] **Retenção de scans** — a rotina roda diariamente às 03:00 e apaga por prazo global (`data.retention.scan-records-days`, padrão 365). Não vaza nada (só deleta). Mas **não é por plano**: existe `deleteOlderThan(cutoff, account)` no repositório, sem nenhum chamador. Se a retenção diferenciada por plano é promessa comercial, ainda não está implementada.

---

## 📦 Prioridade 3 — Dependências & Supply Chain

- [x] **Frontend**: `npm audit` saiu de **15 vulns (10 HIGH) para 0**, com `npm audit fix` simples — sem `--force`, sem mudar `package.json` (todas as correções couberam nos ranges `^` existentes; só o lock mudou). A única dependência de **produção** afetada era `axios` (1.13.5 → 1.19.0, ~18 advisories incluindo SSRF por bypass de `NO_PROXY` e prototype pollution). O resto era build/dev (vite, rollup, esbuild, postcss, cadeia do eslint) — não vai no bundle, mas as falhas de leitura de arquivo do dev server do Vite são reais para quem roda `npm run dev`.
- [x] **Backend**: Spring Boot **3.2.5 → 3.5.16** (3.2.x saiu de suporte em 2024; 4.1 seria migração major, fora de escopo aqui). Também `dnsjava` 3.5.3 → 3.6.5 (CVE-2024-25638, bypass de validação DNSSEC — relevante para um scanner que audita DNS) e `lombok` 1.18.34 → 1.18.46. Traz Tomcat 10.1.55, Spring Security 6.5.11, driver PostgreSQL 42.7.11.
- [ ] **Docker**: escanear a imagem base por CVEs (Trivy/Grype).
- [x] Lock files commitados ✓; nenhuma dependência de fonte duvidosa (tudo Maven Central / npm oficial).

---

## 🏗️ Prioridade 3 — Infra & Deploy

- [x] **Docker**: o container rodava como **root**. Agora usuário dedicado uid/gid 10001, jar copiado `--chmod=444 --chown=root` (o processo não reescreve o próprio binário), base trocada para `17-jre-alpine` (+ `fontconfig`/`ttf-dejavu`, que o AWT do PDFBox precisa), `.dockerignore` criado (o contexto inteiro — incluindo `.env` e `.git` — era enviado ao daemon), `HEALTHCHECK` adicionado e `EXPOSE`/porta alinhados (dizia 8080, app escuta 8081). Nenhum segredo embutido na imagem. **Verificado rodando**: `--read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges` sobe com health UP; flags documentadas no README.
- [~] **Postgres**: o `docker-compose.yml` publicava `"5434:5432"`, que o Docker bind em `0.0.0.0` — banco de desenvolvimento com senha conhecida acessível para toda a rede local. Agora `"127.0.0.1:5434:5432"` e senha vinda do `.env`. **Falta**: backup + restore testados.
- [x] **Actuator**: `management.endpoints.web.exposure.include=health,info`, `show-details=never`, `info.env.enabled=false`. `env`/`heapdump`/`beans`/`mappings` não são sequer expostos pelo Boot, e no `SecurityConfig` só `/actuator/health` e `/actuator/info` são `permitAll` — qualquer outro caminho cai em `anyRequest().authenticated()`.
- [x] Sem endpoints de debug em produção — nenhum Swagger/OpenAPI no classpath, actuator restrito a `health`/`info`, e o `devtools` do Spring é `optional`/runtime-scoped (não vai no jar de produção).
- [ ] Firewall / security groups; portas mínimas abertas. *(depende do host escolhido — Postgres já saiu de `0.0.0.0` no compose local, ver Etapa 1)*
- [x] Logs sem dado sensível — varrido: nenhum log de senha, token, chave ou segredo. O `AsyncScanService` era a exceção real (devolvia a exceção interna crua na resposta) e foi corrigido na Rodada 1.
- [ ] Monitoramento (Sentry/UptimeRobot — opcionais do handoff). ⚠ Se usar health check externo, aponte para `/actuator/health` **depois** da correção do indicador de e-mail (Etapa 5) — antes dela, respondia 503 permanentemente.

---

## 🖥️ Prioridade 3 — Frontend específico

- [ ] **Source maps** NÃO vão pra produção (`vite build` — checar; o próprio scanner detecta isso).
- [x] Sem segredo no bundle — só 3 usos de `VITE_*` no código, todos `VITE_API_URL`. `.env` do frontend deixou de ser versionado; `.env.example` deixa explícito que toda `VITE_*` é pública.
- [x] Sem `dangerouslySetInnerHTML` com dado de usuário — zero ocorrências em `Frontend/src`.

---

## ✅ Ordem sugerida no chat novo
1. **Motor de scan / SSRF** (P0 — o risco que define este produto).
2. **Auth + Authz + isolamento multi-tenant** (P1) — IDOR é o achado mais comum.
3. **Injeção (SQLi/XSS/deserialização)** (P1).
4. **Dogfooding**: publicar e rodar o CyberAudit contra ele mesmo.
5. **Segredos, billing, deps, infra** (P2/P3).
6. Rodar `/security-review` no código e um scanner externo pra cruzar.

> Observação: uma revisão de CÓDIGO + dogfooding cobre muito, mas antes do lançamento público vale um **pentest externo** (mesmo que básico) por outra pessoa/ferramenta, pra pegar o que a auto-análise não vê.

---

## 📌 Rodada 1 — 2026-08-03/04 (P0 + parte do P1)

**Feito:** todo o P0 (motor de scan) exceto "injeção nos probes", mais os IDORs de
histórico/scan async e os limites que faltavam. 61 testes novos (`src/test/`, o
projeto não tinha nenhum).

**Quebras de compatibilidade a saber antes do deploy:**

1. **Tokens de posse de domínio mudaram.** A derivação passou de
   `UUID.nameUUIDFromBytes(MD5)` para HMAC-SHA256 com segredo do servidor. Todo
   arquivo `/.well-known/cyberaudit.txt` já publicado por clientes ficou inválido e
   precisa ser regerado (`GET /scan/verify-token?host=…`). Como o token agora depende
   do segredo, **trocar `JWT_SECRET` (ou definir `DOMAIN_VERIFICATION_SECRET`)
   invalida todos os tokens de novo** — se for rotacionar em produção, defina
   `domain.verification-secret` separado e estável desde já.
2. **`/history/*` agora exige conta.** Requisição sem `Account` associada responde
   401/403 em vez de devolver dados de todo mundo.
3. **Guest atrás de NAT/proxy compartilha o dono do scan async.** Ver
   `FORWARD_HEADERS` acima.

**Próximos passos sugeridos** (ordem do doc): injeção nos probes (P0), auth/sessão
(P1), IDOR de domínios/api-keys/usuários (P1), `escHtml` no `EmailService`, depois
dogfooding e P2/P3.

---

## 📌 Rodada 2 — 2026-08-04 (fecha P0; auth/sessão e isolamento multi-tenant)

**Feito:** último item do P0 (injeção nos probes), toda a Prioridade 1 de
autenticação/sessão e o isolamento multi-tenant restante. +5 testes (66 no total).

**Os três achados mais graves desta rodada** — todos exploráveis por qualquer
pessoa com acesso à internet, sem conta prévia:

1. **Bypass de 2FA.** O token pre-auth (senha OK, 2FA pendente) alcançava
   `/auth/2fa/**` inteiro, inclusive `DELETE /auth/2fa/totp`. Com só a senha da
   vítima, o atacante desativava o segundo fator dela e entrava.
2. **Escalada por auto-registro.** `/auth/register` é público e entrega
   `Role.OWNER`. O role era tratado como "equipe da plataforma": qualquer cadastro
   listava e administrava usuários de todas as contas, lia convites pendentes
   alheios (com o link de aceite) e pulava a prova de posse do scan ativo.
3. **Scan ativo contra terceiros.** Conta EMPRESA scaneava qualquer domínio, e a
   heurística de posse era invertida (dispensava a checagem quando o alvo parecia
   bem configurado). Port scan e probes de injeção contra terceiros saindo do IP
   do CyberAudit.

**Quebras de compatibilidade a saber antes do deploy:**

1. **Scan ativo agora exige domínio verificado, sem exceção de plano.** Conta
   EMPRESA precisa cadastrar e verificar o domínio como todo mundo. O upsell do
   plano deixa de ser "qualquer domínio" e passa a ser "domínios ilimitados".
2. **`PLATFORM_STAFF_EMAILS` nasce vazio → ninguém tem privilégio cross-tenant**,
   nem o OWNER original. Defina com os e-mails da sua equipe se precisar da
   dispensa de posse para suporte.
3. **Senha mínima de 8 caracteres** agora vale no `setup` e no aceite de convite.
   Contas existentes com senha curta continuam logando (a política só roda na
   criação); force troca se houver alguma.
4. **BCrypt subiu para custo 12** nas senhas. Hashes antigos seguem validando; o
   primeiro login de cada usuário fica ~4× mais lento até a senha ser trocada.
   API keys ficaram em custo 10 de propósito.
5. **Lockout de login** (5 falhas/conta, 20/IP, 15 min) é em memória: em deploy
   multi-instância cada nó conta o seu, e um atacante pode travar o login de uma
   vítima por 15 min. Trade-off aceito e documentado no `AuthThrottleService`.

**Pendências conhecidas** (não são regressões, são itens ainda abertos):

- `totpSecret` guardado em texto no banco.
- Desativar 2FA não exige re-autenticação (senha ou código atual).
- Token JWT no `localStorage` do frontend (decisão de arquitetura pendente).
- Restam P2/P3 inteiros: dogfooding, segredos em produção, billing, dependências,
  infra, LGPD.

---

## 📌 Rodada 3 — 2026-08-04 — Etapa 1: Segredos & configuração (P2)

**Feito:** histórico dos dois repos varrido, defaults perigosos removidos, banco de
dev fechado para a rede local, variáveis novas documentadas.

### 🔴 AÇÃO PENDENTE DO DONO DO REPO — segredo em histórico público

`31082005@JoaoAriza-cyberaudit-chave-segura!!` foi commitado como default de
`jwt.secret` e está em `origin/main` de um repositório **público**
(`github.com/JoaoAriza/cyberaudit-backend`), nos commits `7edf6a4` e `65e0e0f`.

O `.env` local usa outro valor, então **não é o segredo em produção** — o impacto
direto é baixo. O que precisa ser feito, em ordem de importância:

1. **Nunca usar essa string como `JWT_SECRET`** em nenhum ambiente. Considere-a
   pública e permanentemente queimada.
2. **Se esse padrão (data de nascimento + nome) for reaproveitado em senhas
   pessoais, trocar** — está indexável no GitHub e associado ao seu nome de usuário.
3. **Reescrever o histórico é opcional e tem custo.** Como o valor não é o segredo
   em uso, limpar o histórico serve mais para higiene do que para conter dano.
   Se decidir fazer: `git filter-repo` ou BFG + `push --force`, avisando quem
   tiver clones. Atenção: o GitHub **mantém os blobs antigos acessíveis por SHA**
   mesmo após o force-push — é preciso abrir chamado no suporte para expurgo real.
   Enquanto isso não acontece, o item 1 é o que de fato protege.

### Corrigido nesta etapa

- `spring.datasource.password` não tem mais o default `cyberaudit123`: deploy sem
  `DB_PASSWORD` falha no boot em vez de subir com senha de exemplo pública.
- `docker-compose.yml`: senha vem do `.env` (era hardcoded) e a porta passou de
  `"5434:5432"` (bind em `0.0.0.0` — banco exposto à rede local inteira) para
  `"127.0.0.1:5434:5432"`.
- `Frontend/.env` saiu do controle de versão (`git rm --cached`); `.env.example`
  criado avisando que toda `VITE_*` vai para o bundle público.
- `.env.example` do backend passou a documentar as 6 variáveis novas das rodadas
  1 e 2 — antes as duas que bloqueiam o deploy (`PLATFORM_STAFF_EMAILS`,
  `FORWARD_HEADERS`) não estavam em lugar nenhum.

**Nota de compatibilidade:** quem já tem `.env` local não é afetado — o boot e o
`docker compose config` foram verificados. Clone novo agora precisa preencher
`DB_PASSWORD` antes de subir qualquer coisa, o que é o comportamento desejado.

---

## 📌 Rodada 3 — Etapa 2: Billing / Mercado Pago (P2)

A base já era sólida: o upgrade nunca sai do corpo do webhook (relê o status na API
do MP), o preço vem da config do servidor, e os endpoints de assinatura derivam a
conta do principal autenticado — não há id de cliente em lugar nenhum, então IDOR
não se aplica. Três furos corrigidos:

1. **Webhook aberto se faltasse o secret.** `verifySignature` retornava `true`
   quando `MP_WEBHOOK_SECRET` estava vazio — a proteção sumia exatamente no cenário
   mais provável, esquecer a variável no deploy. Agora só pula sem `MP_ACCESS_TOKEN`
   (dev/sandbox); com MP ativo e sem secret, rejeita e loga o motivo.
2. **Upgrade sem conferir o valor.** O handler liberava o plano só com base no
   status `authorized`. Passou a exigir que o valor cobrado pelo MP cubra o preço
   configurado — se a resposta trouxer valor menor, recusa e loga.
3. **Webhook sem rate-limit.** Endpoint público onde cada notificação aceita gera
   uma chamada de saída à API do MP. Teto de 60/min por IP.

Também: comparação do HMAC em tempo constante.

**Nada disso muda comportamento para deploy já configurado corretamente** (com
`MP_ACCESS_TOKEN` + `MP_WEBHOOK_SECRET`). Quem estiver rodando com access token de
produção e **sem** webhook secret vai começar a receber 401 no webhook — que é o
ponto: era uma porta aberta.

**Pendência anotada:** não há checagem de frescor no `ts` da assinatura (replay de
notificação capturada). Impacto baixo de propósito — como o handler relê o status
atual na API do MP, um replay só reaplica o estado real. Adicionar janela de tempo
exigiria acertar a unidade do timestamp do MP e arriscaria quebrar billing por
clock skew; não vale o risco agora.

---

## 📌 Rodada 3 — Etapa 3: Transporte, headers e CORS (P2)

### 🔴 O segredo TOTP estava sendo enviado para um terceiro

Achado por acidente ao validar o `img-src` da CSP nova. O frontend montava o QR code
do 2FA assim:

```
https://api.qrserver.com/v1/create-qr-code/?data=<otpauth://totp/...?secret=SEGREDO>
```

Ou seja: **a cada setup de TOTP, o seed completo do segundo fator e o e-mail do
usuário iam na query string de um serviço externo.** Quem controlasse, observasse ou
tivesse acesso aos logs daquele serviço (ou de qualquer proxy no caminho) passaria a
gerar os códigos 2FA daquele usuário indefinidamente — comprometimento permanente do
segundo fator, sem nenhum rastro do lado do CyberAudit.

Corrigido: o QR passou a ser renderizado no servidor (`ZxingPngQrGenerator`, já no
classpath via `totp-spring-boot-starter`) e devolvido como data URI PNG no campo
`qrImage`. O segredo não sai mais da nossa origem. `qrUri` continua no payload para
quem prefere digitar o código manualmente.

**Ação recomendada:** todo usuário que já ativou TOTP teve o segredo exposto. O
prudente é pedir que refaçam o setup do autenticador antes do lançamento.

### Demais correções

- **Frontend sem CSP nenhuma** (este doc afirmava o contrário). CSP agora é injetada
  no build; script de tema saiu de inline para `public/theme-init.js`, o que permite
  `script-src 'self'` em vez de `'unsafe-inline'`.
- **CORS**: `allowedOriginPatterns` → `allowedOrigins`, boot falha com `*` ou vazio,
  headers permitidos/expostos deixaram de ser `*`.
- **Headers da API**: faltavam `Referrer-Policy` e `Permissions-Policy`; a CSP era
  fraca demais para o que é (uma API). Adicionado `Cache-Control: no-store` fora do
  `/badge/`.
- **`vercel.json` + `public/_headers`** para `frame-ancestors`/HSTS, que `<meta>` não
  suporta. Como o host de produção ainda não está definido (o README cita Vercel,
  Cloudflare Pages, Netlify e nginx), os dois formatos foram incluídos —
  **confira que o host escolhido está lendo um deles**.
- `build.sourcemap = false` explícito no `vite.config.ts` (já era o default; agora não
  vira `true` num ajuste distraído). Build verificado: nenhum `.map` no `dist/`.
- `BadgeController` emitia **dois** headers `Cache-Control` com valores diferentes
  (`max-age=300` e `no-cache, max-age=300`) — bug pré-existente, agora um só.

**Verificado no navegador**: com o script de tema externo, `data-theme` continua
aplicado antes do paint e o app renderiza normalmente. Headers da API conferidos com
`curl` numa resposta real.

---

## 📌 Rodada 3 — Etapa 4: DoS restante e validação de tamanho (P2)

A maior parte deste bloco já tinha sido feita nas rodadas 1 e 2 (limite global de
scans, cotas de guest/plano nos 4 endpoints de scan, lockout de login/2FA). Restava
"geração de PDF com limite de recurso" — e o recurso sem limite não era o PDF, era o
**logo da marca**.

**Bomba de descompressão no logo.** A validação existente media apenas o comprimento
da string base64 (280 KB). Um PNG de ~90 bytes pode declarar `50000x50000` no IHDR:
passa folgado no limite de tamanho e vira ~7,5 GB de bitmap quando o PDFBox for
desenhar o cabeçalho. Como o logo fica salvo na conta e é usado em **toda** exportação
de PDF, um único `PUT /account/branding` bastaria para derrubar o processo a cada
relatório gerado dali em diante.

`BrandLogoValidator` passou a checar, em ordem: comprimento do base64 → bytes
decodificados → assinatura de arquivo (PNG/JPEG, não confia em extensão nem no
prefixo `data:`) → dimensões e pixels totais lidos do **cabeçalho** (sem decodificar
os pixels, então é barato). Aplicado tanto na gravação quanto no render — contas que
já tinham logo salvo antes desta mudança também passam pela checagem.

O teste do ataque constrói um PNG de ~90 bytes declarando 50000×50000 e afirma que o
arquivo é minúsculo, para garantir que ele está exercitando a checagem de dimensões e
não caindo no limite de tamanho antes.

**Também**: `name`/`email` no registro e `brandReportName` não tinham teto — acima de
255 chars a inserção estourava na coluna e o cliente recebia 500 em vez de 400.

**Observação anotada, não corrigida:** Spring MVC não impõe teto para corpo JSON
(`maxPostSize` do Tomcat só vale para form-urlencoded). Um POST com JSON de centenas
de MB seria desserializado em memória. Os endpoints que aceitam corpo são todos
autenticados ou já têm rate-limit, o que reduz muito o alcance; fechar de vez pediria
um filtro de `Content-Length`. Vale avaliar junto com a configuração do proxy reverso,
que costuma ser o lugar certo para esse limite (`client_max_body_size` no nginx).

---

## 📌 Rodada 3 — Etapa 5: Dependências (P3)

**Frontend: 15 vulns (10 HIGH) → 0**, com `npm audit fix` simples. Nenhum `--force`,
nenhuma mudança em `package.json` — todas as correções couberam nos ranges `^` que já
existiam, então só o `package-lock.json` mudou. Build, typecheck e app no navegador
verificados depois.

A distinção que importa: **só `axios` era dependência de produção** (vai no bundle).
1.13.5 → 1.19.0 fecha ~18 advisories, incluindo SSRF por bypass de `NO_PROXY` e vários
gadgets de prototype pollution. O resto (vite, rollup, esbuild, postcss, cadeia do
eslint, babel) é build/dev: não chega ao usuário final, mas as falhas de leitura
arbitrária de arquivo do dev server do Vite são risco real para quem roda
`npm run dev` fora de rede confiável.

**Backend: Spring Boot 3.2.5 → 3.5.16.** A 3.2.x saiu de suporte OSS em 2024, então
estava sem correções de segurança há mais de um ano. Fui para a última 3.x em vez da
4.1 disponível — 4.x é migração major (Spring Framework 7) e não cabe numa revisão de
segurança. Também `dnsjava` 3.5.3 → 3.6.5 (CVE-2024-25638, bypass de validação DNSSEC,
particularmente irônico num scanner que audita DNS) e `lombok` → 1.18.46.

87 testes passam e a aplicação sobe no 3.5.16.

### Três comportamentos suspeitos que investiguei — e NÃO são do upgrade

Depois de subir, `/auth/login` com credencial errada devolvia 403, endpoint autenticado
sem token devolvia 403, e `/actuator/health` devolvia **503**. Antes de atribuir ao
upgrade, voltei o `pom.xml` para 3.2.5 e repeti os três testes: **resultado idêntico**.
São pré-existentes.

**Corrigido — `/actuator/health` respondia 503:** o indicador de saúde de e-mail do
Boot tenta autenticar no SMTP; sem `MAIL_PASSWORD` ele falha e derruba o health
agregado para DOWN. Em produção isso significa **load balancer tirando a instância de
rotação com a API 100% saudável** — e, mesmo com e-mail configurado, uma queda
transitória do SMTP faria o mesmo. E-mail é recurso opcional (existe a flag
`mail.enabled`), então `management.health.mail.enabled=false`. Verificado: voltou a
`{"status":"UP"}`.

**Anotado, não corrigido — 403 onde deveria ser 401:** não há
`AuthenticationEntryPoint` configurado, então o `ExceptionTranslationFilter` cai no
`Http403ForbiddenEntryPoint` padrão. Não é falha de segurança (o acesso é negado nos
dois casos), mas o frontend só redireciona para o login quando vê 401 — com 403, um
token expirado deixa o usuário preso numa tela de erro genérica. Correção é de UX/API,
mexe no fluxo de auth, e não quis embutir num commit de dependências.

**Anotado — `ddl-auto=update` falha em ALTER:** o boot loga
`alter table scan_records alter column origin set data type VARCHAR(20) DEFAULT 'MANUAL'`
→ erro de sintaxe no Postgres. É WARN e não impede o boot (a coluna já existe), mas
confirma o que o próprio README do backend já diz: produção pede migrations
versionadas (Flyway/Liquibase). Mesma família do problema conhecido de `ddl-auto` não
atualizar CHECK constraints de enum.

---

## 📌 Rodada 3 — Etapa 6: Infra e Docker (P3)

**O container rodava como root** — o achado clássico, e o único de fato grave aqui.
Corrigido junto com o resto do hardening do `Dockerfile`:

- usuário dedicado `uid/gid 10001`, sem shell de login;
- jar copiado com `--chown=root:root --chmod=444`: o processo não consegue reescrever
  o próprio binário;
- base `eclipse-temurin:17-jre` → `17-jre-alpine`, com `fontconfig` e `ttf-dejavu`
  instalados porque o PDFBox usa AWT para desenhar o relatório;
- `.dockerignore` criado — o contexto inteiro (incluindo `.env` e o `.git` completo)
  era enviado ao daemon a cada build, mesmo o Dockerfile não copiando esses caminhos;
- `HEALTHCHECK` adicionado;
- `EXPOSE 8080` + `ENV PORT=8080` divergiam da porta real (8081) e o `PORT` não era
  lido por nada. Agora `server.port=${SERVER_PORT:8081}` e o container alinha
  `EXPOSE`/`HEALTHCHECK` com essa variável;
- `-Djava.awt.headless=true` (sem isso o AWT tenta abrir display no container) e
  `-XX:MaxRAMPercentage=75` (o default de 25% desperdiça memória sob limite de container).

**Verificado de verdade, não só escrito**: imagem construída, container executado e
confirmado `uid=10001(cyberaudit)`, health `UP`, libs AWT presentes
(`libawt_headless.so`, `libfontmanager.so`) e `fc-match sans-serif` resolvendo
DejaVu — que era o risco real da troca para Alpine. Depois, executado de novo com
`--read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges`: sobe
normalmente. Essas flags estão documentadas no README do backend, já que
`--read-only` só funciona porque o app não escreve em disco (PDF é gerado em memória).

**Ainda em aberto:** escanear a imagem com Trivy/Grype, e firewall/security groups —
os dois dependem do host de produção, que ainda não está definido.

---

## 📌 Rodada 3 — Etapa 7: LGPD (P3)

### 🔴 O direito ao esquecimento não funcionava

`DELETE /user/account` apagava OTPs, agendamentos, convites e domínios — e então
tentava remover a conta. Mas `scan_records`, `api_keys`, `subscriptions` e
`feedbacks` têm FK para `accounts` **sem `ON DELETE CASCADE`**, então a exclusão
estourava em violação de integridade.

Como **todo scan autenticado grava um `scan_records` com `account_id`**, o efeito
prático era: nenhuma conta que já tivesse usado o produto conseguia ser excluída.
Ou seja, o recurso falhava exatamente para 100% dos usuários reais. Pior, o cliente
recebia **403 com corpo vazio** — o erro de banco não aparecia em lugar nenhum da
resposta, então o usuário via "acesso negado" e concluiria que não tinha permissão
de excluir a própria conta.

**Reproduzido antes de corrigir**: conta criada via `/auth/register`, um scan
executado, `DELETE /user/account` → 403, e login seguinte → 200 (conta intacta). O
log do servidor mostrava
`ERROR: update or delete on table "accounts" violates foreign key constraint ... on table "scan_records"`.

Corrigido com um `AccountDeletionService` dedicado, que remove as dependências na
ordem correta: OTPs, agendamentos, convites, api keys e feedbacks do usuário →
solta as referências opcionais (`feedbacks.reviewed_by`, `app_users.invited_by`) →
para OWNER, remove scan_records, api keys, assinaturas, feedbacks, domínios e
convites da conta → usuário → conta.

**Verificado depois da correção**, mesmo cenário: `DELETE` → 200, login → 403, e no
banco `usuario restante: 0` e `scan_records órfãos: 0`.

### Decisão registrada: audit logs sobrevivem à exclusão

`audit_logs` guarda `accountId` como UUID solto (sem FK), então não impedia nem era
afetado pela exclusão. Mantive assim de propósito: são registros de segurança, cuja
base legal é o legítimo interesse, não o consentimento. Mas eles **contêm e-mail e
nome**, e após a exclusão da conta continuam lá (confirmado: 5 registros
preservados no teste). Isso precisa estar descrito na Política de Privacidade —
prazo de retenção incluído (`data.retention.audit-logs-days`, padrão 365 dias).

### Verificado e correto

- **Export** (`/user/data-export`): devolve só dados do próprio usuário e **não
  inclui `passwordHash` nem `totpSecret`**.
- **Audit logs**: `GET /admin/audit-logs` exige OWNER/ADMIN e filtra por
  `accountId`. Não existe endpoint de exclusão — nem admin apaga rastro pela API.
- **Retenção**: roda às 03:00, apaga por prazo. Não vaza nada.

### Anotado, não corrigido

- **Retenção não é por plano.** Existe `deleteOlderThan(cutoff, account)` no
  repositório, sem nenhum chamador — hoje o prazo é global (365 dias) para todos.
  Se "retenção estendida" for promessa de plano pago, ainda não existe.
- **`SCAN_STARTED` registra a URL completa do alvo.** Se o usuário escanear uma URL
  com credencial na query string, ela fica no audit log.
- **`totpSecret` em texto no banco** (já anotado na Rodada 2).

---

## 📌 Rodada 3 — Etapa 8: escaping nos e-mails (P1 que ficou pendente)

Item que a Rodada 2 deixou marcado `[~]` e voltei para fechar: os templates HTML do
`EmailService` montam o corpo por `String.formatted()`, então cada `%s` é uma
interpolação crua a menos que passe por `escHtml`.

**O que estava errado:**

1. `escHtml` escapava `&`, `<` e `>`, mas **não aspas**. Nenhum valor de usuário cai
   em atributo HTML hoje, mas quem editasse um template no futuro não teria como
   saber disso — `href="%s"` seria explorável sem nenhum aviso.
2. `firstName` entrava **cru** em três templates (scan concluído, alerta de
   degradação, OTP).
3. No template de scan concluído, o parâmetro chamado `host` é na verdade
   `result.getUrl()` — a **URL completa**. O `SsrfGuard` valida esquema e host, mas
   path e query seguem livres, então `https://example.com/?q=<img src=x onerror=…>`
   passava direto para o corpo do e-mail. Nesse mesmo template o `host` também não
   era escapado, enquanto no de degradação era: exatamente o tipo de inconsistência
   que vira bug quando alguém acrescenta um destinatário.

**Severidade real, sem inflar:** não há vetor cross-user vivo. `sendScanComplete` vai
para o próprio usuário (tanto pelo scan assíncrono quanto pelo agendado), e
`sendDegradationAlert` — que é o único que alcança terceiros, os OWNER/ADMIN da
conta — já escapava o `host`. Na prática era auto-injeção na própria caixa de
entrada. Corrigi mesmo assim porque a correção custa cinco linhas, e um produto de
segurança com template de e-mail injetável é indefensável no dia em que alguém
mudar um destinatário.

5 testes novos, incluindo a URL com `<img onerror>` e o nome com `<script>`
verificados no HTML gerado de fato — não só no `escHtml` isolado.
