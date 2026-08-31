# Escopo para o próximo chat

Escrito em 2026-08-28, ao fim da sessão que fechou o plano de execução e corrigiu os
falsos positivos das sondas. Documento autocontido: dá para retomar sem ler o histórico.

O registro do que **já foi feito** está em [PLANO_EXECUCAO.md](PLANO_EXECUCAO.md) e
[HANDOFF.md](HANDOFF.md). Este arquivo cobre só o que sobrou.

---

## 0. Onde as coisas estão

**Backend:** 294 testes, todos passando. Último commit: `22a28ab`.
**Frontend:** catálogo com 925 pares, paridade conferida por script avulso. Último
commit: `cf57856`.

O que esta sessão entregou, em uma linha cada:

- revogação de sessão na troca de senha (`password_changed_at` + filtro JWT)
- sonda de DKIM dirigida pelo provedor revelado por SPF/MX
- `ScanResult.lang` — o laudo carimba o idioma em que foi gerado
- resultado parcial nomeia a verificação que não concluiu, e o módulo acende `⚠`
- **quatro falsos positivos corrigidos** nas sondas (Actuator, Swagger, GraphQL, CRLF)
- SSRF, Directory Listing e Path Traversal passaram a exigir marcador forte ou dois fracos
- trocar de idioma parou de apagar o resultado do scan
- evidências, notas e o módulo Changes seguem o idioma do laudo

---

## 1. Verificações que NÃO foram exercitadas

Isto não é lista de bugs — é lista de coisas que ninguém viu funcionando. Vale abrir
cada uma no navegador com o Backend no ar antes de considerar fechadas.

### 1.1 As duas faixas de aviso de idioma

`AvisoIdiomaDoLaudo` no `App.tsx`. Aparece quando `ScanResult.lang` difere do idioma
da tela. Duas instâncias:

- **scan manual** — com botão "Refazer o scan em {idioma}"
- **modal do scan agendado** — sem botão, de propósito (aquele scan já passou)

A lógica é uma comparação de subtag coberta por `tsc`. O que ninguém viu é a faixa
renderizada, o texto cabendo na largura e o botão refazendo o scan do host certo.

### 1.2 O `⚠` do módulo não verificado

`SidebarNavItem` com `degraded`. Quando `degradedModules` traz o id do módulo, o item
troca `✓ SECURE` por `⚠ NÃO VERIFICADO`. Precisa de um scan com timeout para aparecer —
o caso do print original era `sgsistemas.com.br`, que falhou o fetch a partir do Render.

### 1.3 Modal de planos em inglês

Nunca foi visto em EN. Foram 39 chaves, e é **a tela que vende o produto para o cliente
estrangeiro**.

### 1.4 Telas autenticadas em inglês

Agendamentos, Configurações e Painel Admin ficaram só na varredura estática desde a
etapa 36.4 — exigem sessão, e o `/auth/me` do boot roda antes de qualquer stub.

> **Por que nada disso foi verificado:** o H2 sobe vazio, o app cai no assistente de
> configuração inicial, e completá-lo exige criar conta com senha. A API de produção
> recusa `localhost:4173` no CORS. Com um Postgres local com dados, tudo isso se vê em
> dez minutos.

### 1.5 Confirmar em produção que o CRLF parou de acusar o github.com

O achado `PATH_CRLF_HEADER_BODY` (HIGH, −12) foi corrigido por a regra ser errada —
reflexão no corpo não é response splitting. Mas **não foi reproduzido**: os quatro
payloads voltam 404 sem eco quando testados daqui. Vale um scan do github.com depois do
deploy para confirmar que sumiu.

---

## 2. Português chumbado que ainda chega ao laudo

A varredura desta sessão cobriu as sondas, as notas do score e o módulo Changes. Estes
serviços ficaram de fora e **têm texto em português no campo `evidence`**, que a tela
mostra dentro do card:

| serviço | ocorrências | exemplo |
|---|---|---|
| `TechFingerprintService` | ~21 | `"HTML: React fiber detectado"`, `"cf-ray header presente"` |
| `WafDetectionService` | ~10 | `"Payload malicioso bloqueado (HTTP …)"`, `"Nenhum indicador de WAF encontrado"` |
| `SubdomainTakeoverService` | ~5 | `"CNAME aponta para … não reivindicado"`, `"Conexão recusada: "` |
| `TlsVersionService` | 1 | `"… é deprecated (RFC 8996). Vulnerável a POODLE/BEAST."` |
| `HttpMethodService` | 1 | `risk.description() + " (requer autenticação)"` |

**Receita já estabelecida** (foi assim nos outros cinco serviços):

1. chave em `messages.properties` + `messages_en.properties` com prefixo `evidence.`
2. injetar `MessageCatalog` no construtor do serviço
3. trocar o literal por `catalog.evidence("CHAVE", args)`
4. teste que percorre as chaves e falha se faltar em qualquer um dos dois arquivos

**Atenção ao contrário disso:** `ScanChangeDetector.field` usa valores em **inglês**
(`"certificate validity"`, `"days remaining"`, `"SPF policy"`) no meio de um laudo em
português. Ou entram no catálogo, ou viram rótulo técnico assumido — mas hoje é
inconsistência sem decisão.

---

## 3. Dívida de teste

### 3.1 Guarda de paridade do catálogo no Frontend

O Backend tem teste que compara `messages.properties` com `messages_en.properties` nas
duas direções. **O Frontend não tem teste nenhum.** Os 925 pares de `catalog.ts` foram
conferidos com script avulso a cada etapa — inclusive nesta sessão.

Sem isso, chave sem tradução cai no português e **ninguém percebe**, porque nada quebra.
Montar um runner (vitest) só para essa checagem é decisão à parte, mas é a única peça de
infraestrutura de teste que falta do lado do Frontend.

O script usado está em `scratchpad/` e não sobreviveu ao commit — vale reescrever como
teste de verdade.

### 3.2 Regra `no-shadow` no eslint do Frontend

`t` é nome curto e comum. Na sessão da i18n apareceram cinco sombras da função de
tradução; uma teria derrubado o painel de Subdomain Takeover em runtime, e `any` a
escondia do TypeScript. Hoje não há nenhuma, mas a prevenção é manual
(`grep -nE '\.map\(\s*\(?t\b'`).

### 3.3 Uma armadilha que esta sessão pegou, para não repetir

Escrevi testes de sonda contra um servidor HTTP local e **eles passaram pelo motivo
errado**: `ScannerHttp.sendFollowingSafely` valida no `SsrfGuard`, que recusa
`127.0.0.1` — a requisição nunca acontecia, e o teste passaria com o bug presente.

Regra: serviço que usa `ScannerHttp` **não** pode ser testado por servidor local. Teste
a função de decisão direto. Serviço que usa o próprio `HttpClient` (CrlfService,
SourceMapService) pode.

---

## 4. A mudança grande que resolve três coisas de uma vez

`ScanResult` guardar **ID + parâmetros** em vez de texto pronto, resolvendo o texto na
saída. É mudança de contrato e é grande, mas apareceu três vezes por motivos diferentes:

1. **Cache do scan** — o idioma entrou na chave de cache, então o mesmo host é
   reescaneado uma vez por idioma dentro dos 2 min de TTL
2. **PDF** — os relatórios são inglês por decisão, mas o texto dos achados vem do
   `ScanResult`, montado no idioma da requisição. Cliente em português exporta PDF com
   moldura em inglês e achados em português
3. **Laudo do agendamento** — congelado no idioma em que nasceu, e não há como refazer.
   É por isso que a faixa de aviso daquele modal não tem botão

Enquanto isso não acontece, `ScanResult.lang` (feito nesta sessão) é o remendo honesto:
avisa em vez de fingir.

---

## 5. Operacional com prazo

| # | ação | por quê |
|---|---|---|
| 5.1 | **Backup do Postgres do Render** | plano gratuito expira ~30 dias após a criação (~12/08 → vence por volta de **11/09**). Um dump agora custa nada |
| 5.2 | `deploy/audit-action-check.sql` | o enum `audit_logs.action` não é atualizado pelo `ddl-auto`. Sem rodar, a redefinição de senha quebra ao gravar o log |
| 5.3 | `deploy/cleanup-free-domains.sql` | domínios de contas FREE ainda na base, de antes do gating |
| 5.4 | `MP_ACCESS_TOKEN` de volta para produção | conferir a linha `[MercadoPago]` no boot, que informa o ambiente |

**Nada do que esta sessão fez precisa de `.sql`.** As duas colunas novas
(`password_changed_at`, e os campos de `ScanResult` que vivem dentro do `resultJson`)
são criadas pelo `ddl-auto=update` sozinho.

**Ordem de deploy: Backend antes do Frontend.** Se o Frontend subir sozinho,
`degradedModules` e `lang` vêm `undefined` e os avisos simplesmente não aparecem —
degrada em silêncio, não quebra.

---

## 6. Decisões de produto ainda em aberto

Nenhuma é técnica. Todas mudam o que se implementa.

- **Cancelamento sem carência** — `BillingService.cancelSubscription` rebaixa para FREE
  na mesma transação. Quem assina dia 1º e cancela dia 2 perde o mês pago. A tela avisa
  isso com todas as letras, mas o padrão de mercado é manter até o fim do ciclo
- **Notificação ativa do scan ativo** — hoje existe registro consultável no log de
  auditoria, não aviso. Se a intenção é avisar o responsável, é trabalho novo
- **Bloco D — pagamento internacional** — adiado. Moeda única global (`billing.currency`,
  BRL), `Account.country` capturado e não usado. Gatilhos para retomar: cartão
  estrangeiro recusado, ou volume de fora que justifique moeda local

---

## Ordem sugerida

1. **Operacional 5.1 e 5.2** — têm prazo e um deles bloqueia deploy
2. **Verificações da seção 1** — com Postgres local, é uma tarde e fecha o que já foi
   escrito. Verificar antes de escrever mais é mais barato que o contrário
3. **Seção 2** — o português restante nas evidências, com a receita já estabelecida
4. **3.1** — a guarda de paridade do Frontend, antes que o catálogo cresça mais
5. **Seção 4** — quando houver apetite para mudança de contrato
