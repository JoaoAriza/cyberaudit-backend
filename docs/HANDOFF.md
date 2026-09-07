# Handoff — o que falta

Escrito em 2026-08-24, ao fim da sessão que fez os blocos A, B, C, E e F.
Documento autocontido: dá para retomar sem ler o histórico do chat.

O registro completo do que **já foi feito**, com o porquê de cada decisão, está em
[PLANO_EXECUCAO.md](PLANO_EXECUCAO.md). Este arquivo cobre só o que sobrou.

---

## 0. Antes de qualquer coisa

### 0.1 Commitar os documentos

`docs/PLANO_EXECUCAO.md`, `docs/PROXIMOS_PASSOS.md` e este arquivo **nunca foram
commitados**. Todo o registro das decisões desta sessão está em arquivo não
rastreado — um `git clean` apaga tudo.

```
git -C Backend add docs/ && git -C Backend commit -m "docs: plano de execucao e handoff"
```

### 0.2 Operacional com prazo

| # | ação | por quê |
|---|---|---|
| 0.2.1 | ~~**Backup do Postgres do Render**~~ ✅ **feito em 06/09/2026** | `cyberaudit-2026-09-06-2304.dump`, 343,8 KB, 13 tabelas para 13 entidades JPA. Procedimento em `deploy/README.md` (seção "Backup do banco"), scripts em `deploy/dump-postgres.ps1` e `restore-postgres.ps1`. **Falta a migração para o plano pago** — o Free vence por volta de 11/09 |
| 0.2.2 | Rodar `deploy/audit-action-check.sql` | o enum `audit_logs.action` não é atualizado pelo `ddl-auto`. Sem rodar, a redefinição de senha quebra ao gravar o log |
| 0.2.3 | Rodar `deploy/cleanup-free-domains.sql` | domínios de contas FREE ainda na base, de antes do gating |
| 0.2.4 | `MP_ACCESS_TOKEN` de volta para produção | conferir a linha `[MercadoPago]` no boot, que informa o ambiente |

### 0.3 Ordem de deploy — importa

Tudo abaixo já está **commitado**, mas não sei o que está **no ar**. Se ainda não
subiu, a ordem é obrigatória:

1. **Backend antes do Frontend, sempre.** Três motivos independentes:
   - `GET /billing/plans` — o modal de planos do Frontend depende dele. Sem o
     Backend no ar, a tela de planos mostra só a mensagem de erro
   - `Accept-Language` na allowlist do CORS — o Frontend manda o header em toda
     chamada. Sem a liberação, **o preflight recusa e a API para de responder ao
     navegador**
   - PDF/e-mail como recurso pago — o Backend recusa com 402; a UI precisa da
     versão nova para mostrar o cadeado em vez de deixar o botão clicável

2. **Duas mudanças são visíveis para quem já usa:**
   - Todo FREE **perde o PDF** e a notificação por e-mail
   - Rota fechada passou a responder **401 em vez de 403**. O efeito é o desejado
     (sessão expirada agora derruba para o login em vez de travar), mas é mudança
     de comportamento

---

## 1. Etapa 36.7 — fechar a internacionalização do Frontend

**~100 strings. É o que falta para o bloco C acabar.**

A varredura final achou uma superfície que o levantamento original não previu: eu
dividi o trabalho por TELA, e estas peças nasceram antes de existir i18n (etapas
28–32).

### 1.1 Modal de planos — prioridade dentro da etapa

`PLAN_CARDS`, `rotuloDoRecurso`, confirmação de cancelamento, "Faça login para
assinar" e as mensagens de erro do checkout, em `Frontend/src/App.tsx`.

**É a tela que vende o produto para o cliente estrangeiro.** Hoje um visitante em
EN navega tudo em inglês, clica em "View plans" e cai numa tela em português.

### 1.2 `MODULE_INFO`

`App.tsx`, por volta da linha 800. 23 entradas × 3 textos (o que é, o que faz,
dica) — o modal "Saiba mais" de cada módulo.

Quarta tabela de módulo do arquivo. Mesmo tratamento das outras três: guardar
CHAVES e resolver na renderização. Ver `TECH_RISK`, `HEADER_META` e
`AUDIT_ACTION_KEYS`, já convertidas.

### 1.3 Duas sobras avulsas

- `SidebarNavItem` — "Módulo bloqueado — disponível nos planos pagos"
- `ScheduleScanDetailModal` — um "SERVIÇO" que escapou

### 1.4 Fica de fora, corretamente

- **`TermsModal`** — Termos de Uso e Política de Privacidade. Decisão do dono:
  ficam em português. É documento jurídico, a política responde à LGPD, e uma
  versão em inglês passaria a valer para quem a lê em inglês
- **`"proprietário verificado"`** no `App` — casa mensagem de erro do Backend.
  Traduzir quebra o reconhecimento do erro em silêncio. Existem ~25 strings assim
  no arquivo (`"UnknownHostException"`, `"connect timed out"`…)

---

## 2. Dívida técnica registrada, nunca feita

### 2.1 Etapa 39 — Revogar sessões após troca de senha

Verificado: **não existe** `password_changed_at` no `AppUser`. O JWT anterior segue
válido por até 24h depois da redefinição. Precisa do carimbo no usuário mais
conferência no filtro JWT.

> `sec: redefinir senha invalida as sessoes antigas`

### 2.2 Etapa 41 — DKIM dirigido por evidência

Hoje o `DnsSecurityService` sonda ~40 seletores conhecidos por força bruta. O
`include:` do SPF e o destino do MX revelam o provedor de e-mail e permitiriam
palpite dirigido.

> `perf: sonda de dkim usa o provedor revelado por spf e mx`

---

## 3. Decisões de produto em aberto

Nenhuma é técnica. Todas mudam o que se implementa.

### 3.1 Cancelamento sem carência

`BillingService.cancelSubscription` grava `CANCELLED` e rebaixa a conta para FREE
**na mesma transação**. Quem assina dia 1º e cancela dia 2 perde o mês inteiro que
já pagou.

A tela avisa isso com todas as letras, porque tem de contar o que o código faz. Mas
o padrão de mercado é o contrário: manter o acesso até o fim do ciclo. Mudar exige
guardar a data de expiração e só rebaixar quando ela chegar.

### 3.2 Guarda de paridade do catálogo no Frontend

O Backend tem teste que compara `messages.properties` com `messages_en.properties`
nas duas direções. **O Frontend não tem teste nenhum.** A paridade dos 643 pares em
`catalog.ts` foi conferida com script avulso a cada etapa.

Montar um runner (vitest) só para essa checagem é decisão à parte — mas sem ela,
chave sem tradução cai no português e **ninguém percebe**, porque nada quebra.

### 3.3 Notificação ativa do scan ativo para o responsável

O dono disse que o scan ativo em conta Empresa "vai passar pelo chefe de setor que
vai estar ciente". Hoje existe **registro consultável**, não aviso: o
`ScanOrchestrator` grava `SCAN_STARTED` e `SCAN_COMPLETED` no log de auditoria com
modo, URL e score, e o log aparece no módulo de Relatórios (PRO+). Ninguém é
notificado. Se a intenção é aviso ativo, é trabalho novo e não está em etapa
nenhuma.

### 3.4 Bloco D — pagamento internacional (adiado)

Decisão de 2026-08-24: enquanto o cliente de fora conseguir pagar pelo fluxo atual,
está valendo. Contexto para quando voltar:

- A moeda é **uma só, global**: `billing.currency`, default `BRL`
- `Account.country` é capturado no cadastro e **não é usado em nada do billing**
- O cliente estrangeiro é cobrado em reais, com conversão e IOF do banco dele, num
  checkout do MP em português
- **Gatilhos para retomar:** cartão estrangeiro sendo recusado, ou volume de fora
  que justifique moeda local
- A decisão é **Merchant of Record** (Paddle/Lemon Squeezy — eles respondem pelo
  imposto) **ou gateway** (Stripe — o VAT europeu vira obrigação sua), e **USD fixo
  ou preço por região**
- A Etapa 37 (extrair interface `PaymentProvider`) foi **parada de propósito**:
  sem segundo provedor, é interface com uma implementação só

---

## 4. Melhorias identificadas, não registradas como etapa

### 4.1 Resultado guardar ID + parâmetros em vez de texto pronto

Apareceu **duas vezes** por motivos diferentes, o que sugere que a hora dela vai
chegar:

- **Cache do scan** (Etapa 34): o resultado guardado já traz o texto montado, então
  o idioma entrou na chave de cache. Custa refazer o scan uma vez por idioma no
  mesmo host dentro dos 2 minutos de TTL
- **PDF** (Etapa 35.1): os relatórios são inglês por decisão, mas o texto dos
  achados vem do `ScanResult`, montado no idioma da requisição. Um cliente em
  português exporta PDF com moldura em inglês e achados em português

O conserto dos dois é o mesmo: o `ScanResult` guardar ID + parâmetros, e o texto ser
resolvido na saída. É mudança de contrato e grande.

### 4.2 Regra `no-shadow` no eslint do Frontend

`t` é nome de variável curto e comum. Nesta sessão apareceram **cinco** sombras da
função de tradução; uma delas teria derrubado o painel de Subdomain Takeover em
runtime, e `any` a escondia do TypeScript.

Todas foram renomeadas e hoje não há nenhuma. A prevenção manual é
`grep -nE '\.map\(\s*\(?t\b'` antes de mexer num componente — mas uma regra de lint
resolveria de vez.

---

## 5. Armadilhas do código que custaram tempo nesta sessão

Vale ler antes de mexer no `App.tsx` (7.100 linhas).

1. **Tabela no nível do módulo não tem `t()`.** Quatro já foram convertidas para
   guardar chaves (`TECH_RISK`, `HEADER_META`, `AUDIT_ACTION_KEYS`, e a função
   `fbStatusKey`). `MODULE_INFO` é a que falta.

2. **`sed` com `/g` atravessa componentes.** Substituição global alcança telas de
   outras etapas e vaza o escopo do commit. Sempre delimitar por faixa de linha, e
   conferir o que sobrou depois.

3. **`sed` quebra JSX de duas formas previsíveis:** tira as chaves de atributo
   (`x=t("k")` em vez de `x={t("k")}`) e aninha aspas dentro de chaves
   (`"{t("k")}"`). As duas o `tsc` pega na hora — rodar sempre.

4. **Nem toda string entre aspas é traduzível.** ~25 no `App.tsx` são trechos para
   CASAR mensagem de erro do Backend. Traduzir quebra o reconhecimento em silêncio.

5. **Varredura estática não basta.** Em toda etapa que verifiquei no navegador,
   apareceu sobra que o extrator não pegou — quatro descrições no
   `ActiveChecksPanel`, o rodapé do `ModCard`, o status "FRACO". As telas
   autenticadas (36.4 e parte da 36.5) ficaram **só na varredura estática**, porque
   exigem sessão e o `/auth/me` do boot roda antes de qualquer stub. **Se houver
   Backend rodando, vale abrir Agendamentos, Configurações e o Painel Admin em EN
   antes de considerar aquilo verificado.**
