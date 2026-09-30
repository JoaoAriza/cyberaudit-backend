# HANDOFF — CyberAudit (checkout transparente: o que falta)

> Cole/abra este arquivo no chat novo. Resume o estado atual e o que falta do
> checkout transparente (Pix + cartão). Criado em 2026-09-30 porque a janela de
> contexto do chat anterior encheu.

---

## 0. Contexto rápido

**CyberAudit** = scanner de postura de segurança de sites (TLS, headers, DNS,
exposições, vulnerabilidades comuns → nota 0–100 + relatório PDF).

- **Backend**: `C:\Projetos\Cyberaudit\Backend` — Spring Boot 3.5.16, Java 21,
  PostgreSQL (Render). Deploy: `https://api.cyberauditapp.com`.
- **Frontend**: `C:\Projetos\Cyberaudit\Frontend` — React + TS + Vite (Cloudflare
  Pages). Deploy: `https://www.cyberauditapp.com`.
- **cyberaudit-qa**: `C:\Projetos\Cyberaudit\cyberaudit-qa` — projeto de portfólio de
  QA (Postman/Newman, RestAssured, Cypress, Selenium). Ainda **não é um repositório
  git** — só uma pasta local com o PDF de escopo original e os artefatos que já
  registramos (ver seção 3).

Ambos os repos (Backend/Frontend) estão com push feito e testados em produção até
o último commit de cada um.

---

## 1. O que foi entregue nesta fase (checkout transparente)

**Motivação original**: reduzir dependência do checkout hospedado do Mercado Pago.
Importante lembrar — **isso NÃO reduz a taxa cobrada** (taxa é da forma de pagamento,
não do tipo de checkout); o ganho real é UX/conversão e, com Pix, evitar o
processamento de cartão. Preço do PRO caiu para R$19,99 e do Empresa para R$59,99
nesta mesma janela (motivo diferente: tornar o produto mais acessível na fase inicial).

### Backend
- `POST /billing/checkout/card` — cartão tokenizado no navegador (`card_token_id`
  do SDK do MP), cria `preapproval` recorrente via API. Libera o plano na hora se
  vier `authorized`.
- `POST /billing/checkout/pix` — pagamento único de 1 ciclo (30 dias — Pix comum não
  tem débito automático). Devolve QR code + copia-e-cola. Plano só libera quando o
  webhook confirmar `approved`.
- `Subscription` ganhou `paymentMethod` (CARD/PIX), `mpPaymentId`, `currentPeriodEnd`.
  Novo status `EXPIRED`, rebaixado por job diário (`expirarAssinaturasPixVencidas`)
  quando uma assinatura Pix vence sem renovar.
- Webhook (`/billing/webhook`) agora trata dois topics: `preapproval` (cartão, já
  existia) e `payment` (Pix, novo).
- Rate limit dedicado nos dois endpoints de checkout: 5 tentativas/minuto por
  usuário, **compartilhado** entre cartão e Pix (não é 5+5).
- 16 testes novos (`BillingServiceTest` + `SubscriptionSchemaTest`).

### Frontend
- `CheckoutModal` (abas Pix/Cartão) substituiu o botão que redirecionava pro MP.
- Pix: CPF → QR code + copia-e-cola na tela, com polling em `/billing/subscription`
  até confirmar.
- Cartão: SDK do MP carregado sob demanda, Secure Fields (número/validade/CVV nunca
  tocam nosso DOM), token gerado no navegador.
- CSP liberou `sdk.mercadopago.com` e domínios dos Secure Fields (só no build de
  produção — dev não tem CSP).

### Incidente em produção — já corrigido
`ddl-auto=update` tentou adicionar `payment_method` como `NOT NULL` numa tabela
`subscriptions` que já tinha linhas reais → Postgres recusou → a coluna nunca foi
criada → **todo** endpoint que tocava `Subscription` (inclusive o `/billing/subscription`
que já existia antes desta fase) respondia 401 em vez do erro de verdade. Corrigido
tornando a coluna nullable. Confirmado resolvido em produção pelo usuário.
**Lição**: `ddl-auto` não migra bem contra tabela com dado existente — já tínhamos
um caso assim (`audit_logs`, ver `docs/SECURITY_REVIEW_SCOPE.md`) e caiu de novo.
Considerar Testcontainers com Postgres real pra pegar isso ANTES de produção (ver
seção 2).

---

## 2. O que falta implementar

1. ~~**`VITE_MP_PUBLIC_KEY` não está configurada em lugar nenhum**~~ 🟡 **parcial
   em 2026-09-29** — chave de **produção** (`APP_USR-...`) configurada em
   `Frontend/.env` e `Frontend/.env.production` (gitignored, não vai pro repo).
   **Falta**: adicionar a mesma variável nas variáveis de build do Cloudflare
   Pages e disparar um redeploy — isso só o dono da conta consegue fazer (acesso
   ao dashboard). Sem esse passo, o build publicado continua sem a chave.
2. **Nunca testado contra o Mercado Pago de verdade** — a chave configurada no
   item 1 é de **produção**, não sandbox (`TEST-`) — então cartão de teste do MP
   não serve para validar com ela. Ainda falta: (a) conseguir o par `TEST-`
   (Public Key + Access Token) na aba "Credenciais de teste" do painel MP para
   validar sem risco, e/ou (b) uma transação real de ponta a ponta em produção
   depois do Cloudflare Pages redeploy do item 1. Tudo que foi validado até aqui
   foi: contrato da API do CyberAudit (Postman/Newman) e o bug de schema em
   produção — nunca uma confirmação real de pagamento (Pix aprovado ou cartão
   autorizado).
3. **CSP do SDK do MP é a minha melhor leitura da documentação, não confirmada**
   — `script-src`/`frame-src` em `vite.config.ts` podem precisar de ajuste ao abrir
   o DevTools com uma public key de verdade e ver o que o navegador bloqueia.
4. ~~**CPF só valida tamanho (11 dígitos), não o dígito verificador**~~ ✅ **feito
   em 2026-09-29** — `CpfUtil` (módulo 11, mesmo padrão do `CnpjUtil`) plugado em
   `BillingService.startPixCheckout`. Mensagem de erro não ecoa o CPF (é dado
   pessoal). 12 testes novos em `CpfUtilTest` + 1 em `BillingServiceTest`.
5. ~~**`/billing/subscribe` (checkout hospedado antigo) continua existindo**~~ ✅
   **removido em 2026-09-29** — decisão: sem uso do Frontend e sem teste nenhum,
   não valia manter como fallback morto. Foram junto `BillingService.startSubscription`,
   `MercadoPagoService.createPreapproval` e o helper `checkoutUtilizavel` (só
   existia para o init_point do checkout hospedado) — e o teste dedicado a ele,
   `MercadoPagoCheckoutUrlTest`. 648 testes passando depois da remoção.
6. **Pix Automático (recorrência de verdade) foi propositalmente deixado de fora**
   — o que existe hoje é Pix comum (1 pagamento manual por ciclo). Se for
   implementar depois, é fase separada — tem regra do Bacen própria (pré-aviso de
   cobrança, cancelamento) que não foi pesquisada a fundo ainda.

---

## 3. O que falta testar

### Já feito
- Suíte JUnit/Mockito do Backend (635 testes) cobre a lógica de negócio dos dois
  fluxos de checkout, idempotência do webhook, e o job de expiração.
- Validação de contrato via Postman/Newman (autenticação, validação de entrada,
  rate limit, falha segura sem `MP_ACCESS_TOKEN`) — artefatos em
  `cyberaudit-qa/api-postman/collection.json` + `environment.local.json`.
- Request/response de cada endpoint documentados em
  `cyberaudit-qa/docs/payment-module-requests.md`, com 12 casos catalogados
  (PAY-01 a PAY-12) no formato da matriz do escopo original.

### Falta fazer
1. **Teste de integração real com o MP sandbox** — assim que existir uma credencial
   `TEST-`: confirmar que `createPixPayment`/`createPreapprovalWithCard`/`getPayment`
   batem com o formato real de resposta (hoje só bateram contra a documentação).
2. **Suíte RestAssured** (Fase 3 do escopo do `cyberaudit-qa`, PDF original) — ainda
   não começou. Os 12 casos PAY-01..PAY-12 já catalogados são o ponto de partida.
3. **Cypress E2E do checkout** — nenhum teste de UI ainda. Fluxos mínimos: abrir
   modal → aba Pix → CPF inválido mostra erro → CPF válido mostra QR (mockar a API
   do MP ou usar sandbox); aba Cartão → SDK carrega → Secure Fields aparecem →
   submit gera token (precisa de cartão de teste do MP).
4. **Teste de migração de schema com Postgres real** (Testcontainers, não H2) —
   especificamente pra pegar a classe de bug que acabou de quebrar produção: subir
   um Postgres com uma linha "antiga" (sem a coluna nova) e confirmar que
   `ddl-auto=update` consegue migrar sem erro. H2 com `create-drop` estrutural e
   nunca vai pegar isso — é um teste genuinamente novo pro projeto, não só mais um
   caso na suíte atual.
5. ~~**CPF com dígito verificador inválido mas 11 dígitos**~~ ✅ **decidido e testado
   em 2026-09-29** — agora recusa (ver item 4 da seção 2). Coberto por
   `cpfComDigitoVerificadorInvalidoRecusa` em `BillingServiceTest`.
6. **Revisão de segurança específica da tela de checkout** — CSP realmente
   restritiva (nenhum script/frame fora do necessário), confirmar que nenhum campo
   de cartão cru toca o DOM do CyberAudit (inspecionar via DevTools com o SDK
   carregado de verdade), e teste de que a página de checkout nunca loga
   `cardTokenId`/CPF em texto puro no console ou nos logs do Backend.
7. **Rate limit sob concorrência real** — o teste atual (Postman `pm.sendRequest`
   sequencial) prova a lógica, mas não testa duas requisições literalmente
   simultâneas. Vale um teste de carga leve se o `cyberaudit-qa` chegar na fase de
   RestAssured com threads paralelas.

### Projeto `cyberaudit-qa` como um todo
Continua não iniciado como repositório de verdade — só a pasta local com PDF +
os dois artefatos desta fase. Retomar da Fase 0 (plano de teste formal) quando este
recurso de pagamento estiver estável, ou intercalar: os 12 casos PAY-* já dão
conteúdo real pra começar a Fase 2/3 (Postman + RestAssured) sem esperar o resto
do escopo original (Juice Shop, WireMock, allowlist de SSRF pro ambiente de teste).

---

## 4. Ordem sugerida pro próximo chat

1. Configurar `VITE_MP_PUBLIC_KEY` (bloqueia literalmente tudo de cartão).
2. Conseguir uma credencial `TEST-` do MP e validar os dois fluxos de ponta a ponta
   de verdade (Pix aprovado, cartão autorizado e recusado).
3. Ajustar CSP conforme o que o DevTools acusar nesse teste real.
4. A partir daí, decidir: continuar fechando o recurso de pagamento (CPF checksum,
   remover `/billing/subscribe` antigo) ou migrar o foco pro `cyberaudit-qa` de
   verdade, usando os casos PAY-* como primeiro conteúdo real do projeto de QA.
