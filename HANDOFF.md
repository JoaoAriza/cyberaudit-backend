# HANDOFF — CyberAudit (próxima fase)

> Cole/abra este arquivo no chat novo. Ele resume **o estado atual** do projeto e os
> **próximos passos** (as ideias novas). Foi criado porque a janela de contexto do chat
> anterior encheu.

---

## 0. Contexto rápido (para o novo chat se situar)

**CyberAudit** = scanner de postura de segurança de sites. A partir de uma URL, avalia
TLS, headers, DNS/e-mail, exposições e vulnerabilidades comuns, e dá uma nota 0–100 com
nível de risco, issues e relatórios (texto/PDF).

- **Backend:** `Seg_site` — Spring Boot 3.2.5 + Java 17 + PostgreSQL. Ver `README.md`.
- **Frontend:** `cyberaudit-ui` — React 19 + TS + Vite. Ver o `README.md` dele.
- Scan passivo (aberto, com rate-limit) × ativo (autenticado + prova de propriedade).

**O que a última rodada entregou** (já commitado):
- Anti-falso-positivo: SsrfGuard, CSP via `<meta>`, apex via Public Suffix List,
  CVE "potencial", WAF por bloqueio diferencial, host-header no body = LOW,
  debug-endpoints por marcador.
- Resultado parcial honesto (`moduleStatus` OK/TIMEOUT/SKIPPED), `analyzedHost`,
  auditoria de **hosts relacionados** (api./server./www.).
- Cor do score por nível de risco (Scanner e Histórico consistentes).
- Layout da tabela de Agendamentos, limpeza de comentários, READMEs dos dois repos.

**Backlog técnico já identificado (não feito):**
- Sem crawler → probes de injeção (XSS/SQLi/SSRF/LFI/CRLF) só rodam com `?param=`.
- SSRF: DNS-rebinding não fechado (residual).
- PSL é snapshot → refresh periódico.
- `App.tsx` é monolito (~6k linhas) → candidato a refactor por feature.
- ⭐ **Falta limite global de scans concorrentes** (semáforo no `ScanOrchestrator`) —
  é a melhoria #1 de capacidade antes de escalar hardware.

---

## 1. Tarefas desta próxima fase (as ideias novas)

### ✅ Tarefa 1 — Mover o projeto do OneDrive para o disco C: (FAZER PRIMEIRO)

**Por quê:** o OneDrive sincroniza `.git/`, `node_modules/`, `target/`, trava arquivos e
corrompe o repositório → causa erros de build. Tem que sair do OneDrive.

**Passos (fazer com o OneDrive pausado e as IDEs fechadas):**

```powershell
# 1) Pausar o OneDrive (ícone na bandeja → Pausar sincronização)

# 2) Copiar os repos para fora do OneDrive, SEM as pastas regeneráveis (mantém o .git)
$srcBack = "C:\Users\joaoa\OneDrive\Documentos\Linguagens_Codigos\JAVA\seg_sites\Seg_site"
$srcFront = "C:\Users\joaoa\OneDrive\Documentos\Linguagens_Codigos\JAVASCRIPT\front_cyberaudit\cyberaudit-ui"

robocopy $srcBack  "C:\Projetos\CyberAudit\Seg_site"      /E /XD target .idea
robocopy $srcFront "C:\Projetos\CyberAudit\cyberaudit-ui" /E /XD node_modules dist

# 3) Validar no destino
cd C:\Projetos\CyberAudit\Seg_site;      git status; mvn -o compile
cd C:\Projetos\CyberAudit\cyberaudit-ui; git status; npm install; npm run build

# 4) Só depois de validar, apagar as cópias antigas do OneDrive
```

**Conferir o `.gitignore`** de cada repo inclui: `target/`, `node_modules/`, `dist/`, `.env`.
Depois de mover, o working directory dos próximos comandos passa a ser `C:\Projetos\CyberAudit\...`.

---

### 💳 Tarefa 2 — Fluxo de pagamento + conta destino

**Decisão de provedor (a definir):**
- **Stripe** — melhor DX, assinaturas prontas, aceita Pix no BR. Ótimo pra SaaS.
- **Mercado Pago** — maior alcance no Brasil (Pix + boleto + cartão), checkout simples.
- **Asaas / Pagar.me** — alternativas BR (Pix/boleto/cartão), boas pra recorrência.
- Recomendação: **Stripe** (se o público é mais tech) ou **Mercado Pago** (alcance BR).

**"Para qual conta vai o dinheiro":** cai na **sua conta de merchant** dentro do provedor
escolhido, que repassa pro seu **banco** (isso é configurado no *dashboard do provedor*,
não no código). No código ficam só as **chaves** (secret) + o **webhook** que ativa o plano.

**Integração (usa o que já existe):** o projeto já tem `Plan` + `PlanLimitService` +
`Account`. Fluxo: usuário assina no Checkout do provedor → provedor manda **webhook** de
confirmação → backend faz upgrade do plano da `Account` → limites liberam.

**Passos:** escolher provedor → criar conta merchant → plugar Checkout/Subscription →
handler de webhook (assinatura confirmada / cancelada / falha) → tela de billing no front.

> ⚠️ Regra: o assistente **não insere credenciais financeiras nem move dinheiro**. Você
> configura as chaves e a conta; o código só faz a integração e reage ao webhook.

---

### 🔑 Tarefa 3 — APIs / chaves a obter (checklist p/ ficar funcional)

| Serviço | Para quê | Custo | Env var |
|---|---|---|---|
| **NVD API key** | Aumenta rate-limit da correlação de CVE | Grátis (registrar) | (novo) |
| **E-mail (Brevo/SendGrid/Mailgun/Gmail)** | Notificações, OTP, convites | Grátis (free tier) | `MAIL_*` |
| **Provedor de pagamento** (Stripe/MP) | Assinaturas | % por transação | (novo) chave + webhook secret |
| **Domínio** (registrar) | app.seudominio + api.seudominio | ~R$40/ano | — |
| **Let's Encrypt** | TLS | Grátis | — |
| **crt.sh / OSV / PSL** | CT logs / vuln / apex | Grátis, sem chave | — |
| **Sentry** (opcional) | Monitorar erros | Grátis (free tier) | (novo) |
| **UptimeRobot** (opcional) | Uptime / alerta de queda | Grátis | — |

`JWT_SECRET` e `DB_*` já existem no `application.properties`.

---

### 🌗 Tarefa 4 — Modo escuro / claro

O frontend **já usa variáveis CSS** (`index.css` `:root` tem `--bg`, `--surface`, `--text`…),
então o toggle é barato:
1. Definir a **paleta light** (valores das variáveis) — **cores a decidir com você**.
2. Toggle no header seta `data-theme="light"` no `<html>` e persiste em `localStorage`.
3. CSS: `:root[data-theme="light"] { --bg: …; --surface: …; … }` sobrescreve o dark.

Hoje a paleta é dark-only; falta só criar a versão clara e o botão.

---

### 💬 Tarefa 5 — Campo de feedback (contestar um achado)

Cliente que achar que um resultado está errado marca "isso está errado?" num finding/módulo,
escreve o motivo, e o admin tria → vocês debatem. Bônus: vira **dado real de falso positivo**
pra melhorar o produto.

- **Backend:** entidade `Feedback` (scanId/host, módulo/finding, usuário, mensagem,
  status: OPEN/REVIEWING/RESOLVED). Endpoints: submeter + admin listar/responder.
  Pode reusar `AuditService` / notificação por e-mail.
- **Frontend:** botão + modal no card do finding/módulo → envia; view de admin pra triar.
- **A decidir:** feedback por-finding (mais granular) ou por-scan (mais simples)?

---

## 2. Perguntas a resolver no chat novo

1. **Provedor de pagamento:** Stripe, Mercado Pago ou Asaas?
2. **Planos e preços:** quais tiers e valores? (o `Plan`/`PlanLimitService` já existe)
3. **Modo claro:** qual paleta de cores?
4. **Feedback:** por-finding ou por-scan?
5. Ordem: sugiro **Tarefa 1 (mover) → 3 (chaves) → 2 (pagamento) → 5 (feedback) → 4 (tema)**.

---

## 3. Próximo projeto separado (futuro): DepGuard

Já discutimos o escopo de uma **suíte DevSecOps** (scanner de dependências + SBOM +
scanner de segredos, com GitHub App que comenta no PR). É um projeto **à parte** — não
misturar com o CyberAudit. Quando for a hora, começar pela "Fase 0" (npm + segredos,
saída JSON+SARIF+CycloneDX). Reaproveita a experiência de CVE/OSV, DNS e relatórios daqui.
