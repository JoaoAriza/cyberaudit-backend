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

1. ~~**`VITE_MP_PUBLIC_KEY` não está configurada em lugar nenhum**~~ ✅ **feito em
   2026-09-30** — chave de **produção** (`APP_USR-...`) configurada em
   `Frontend/.env`, `.env.production` (gitignored) e nas variáveis de build do
   Cloudflare Pages (Settings → Variables and secrets), com redeploy confirmado.
   Pegadinha encontrada no processo: salvar a variável no painel **não** dispara
   deploy novo sozinho — precisou de um commit vazio (`chore: forcar redeploy...`)
   pra reconstruir com a variável já presente.
2. 🟡 **Cartão testado parcialmente / Pix confirmado de ponta a ponta com dinheiro
   real, em 2026-09-30.**
   - **Cartão**: com a public key de **produção**, preenchi o formulário real
     (nome/CPF/validade/CVV) usando o cartão de teste *público* do MP
     (`5031 4332 1540 6351`) e cliquei Pagar: o SDK gerou o token, nosso backend
     recebeu e chamou o MP de verdade, e o MP respondeu `400: Card Number can't be
     empty, please generate a valid card token` — rejeição correta e esperada
     (produção recusa esse número de propósito, é antifraude). Confirma que o cano
     cartão→backend→MP está de pé, mas falta uma autorização de verdade (precisa do
     par `TEST-` em sandbox, ou um cartão real de alguém).
   - **Pix**: ✅ **confirmado de verdade, com pagamento real de R$19,99** (estornado
     depois, sem custo líquido). `AUTHORIZED` chegou sozinho ~25s depois do pagamento,
     `currentPeriodEnd` certo (+30 dias). No caminho, achei e corrigi **três**
     problemas de configuração no painel do Mercado Pago (nenhum era bug de código):
     1. O Webhook (`Developers > Webhooks`) estava com a URL do **Frontend**
        (`www.cyberauditapp.com`) e/ou só configurado para o ambiente de teste — a
        notificação nunca tinha pra onde ir. Corrigido pra
        `https://api.cyberauditapp.com/billing/webhook`.
     2. O evento **"Pagamentos" não estava marcado** nesse Webhook — só "Planos e
        assinaturas" (preapproval). Sem isso, o MP nunca tenta notificar um Pix
        aprovado, nem contra a URL certa. Existia também um **IPN** (mecanismo
        antigo, tela separada) com "Pagamentos" marcado — mas o IPN não manda
        `x-signature`, então cairia direto no `verifySignature` mesmo se disparasse.
     3. O **`MP_WEBHOOK_SECRET` no Render estava desatualizado** — diferente do
        secret que o MP usa pra assinar esse webhook especificamente. Descoberto
        rodando o "Simular" do MP (manda um payload de teste com id fake `123456`):
        tomava 401 tanto pra `payment` quanto pra `preapproval`, o que apontou pra
        validação de assinatura (comum aos dois), não pra lógica de negócio. Depois
        de corrigir o valor no Render e reiniciar, o mesmo teste simulado passou.
   - **Achado de bug real, não de configuração**: `BillingService.getSubscription`
     usa `findFirstByAccountOrderByCreatedAtDesc` — sempre a assinatura MAIS
     RECENTE. Um Pix pago e depois um segundo Pix gerado sem pagar (pra
     testar de novo) faz o sistema "esquecer" o pago, porque o não-pago é mais
     novo. Registrado como pendência na seção 2, item 9.
   - Um pagamento de teste (11:31 do dia) ficou órfão porque o evento "Pagamentos"
     ainda não estava habilitado quando ele foi feito — sem retroatividade, o MP não
     reenvia notificação de evento não-subscrito. Estornado pelo próprio usuário, sem
     custo líquido; o teste que confirmou tudo foi um Pix novo, gerado e pago depois
     dos três reparos acima.
3. ~~**CSP do SDK do MP é a minha melhor leitura da documentação, não confirmada**~~
   ✅ **corrigida e confirmada em produção em 2026-09-30**, com a public key de
   verdade — precisou de 3 rodadas (CSP bloqueia em cascata, cada ajuste revela a
   próxima camada):
   - `connect-src`: faltavam `secure-fields.mercadopago.com` e
     `api-static.mercadopago.com` (o SDK busca esses dois ANTES de montar o
     iframe do cartão — sem eles, a caixa aparecia mas não aceitava nenhum toque).
   - `frame-src`: faltava `secure-fields.mercadopago.com` (é a origem real do
     iframe do cartão, não `www.mercadopago.com`).
   - `script-src`: o SDK injeta pelo menos **dois** `<script>` inline pro handshake
     do Secure Fields — cobertos por hash (`'sha256-...'`), não `'unsafe-inline'`,
     pra não afrouxar a CSP do app inteiro.
   Confirmado funcionando: campo de número aceita dígito, formata, Validade/CVV
   ativam, e o Pagar chega de verdade até a API do MP (ver item 2).
   **Ainda bloqueado de propósito, sem impacto no checkout** (confirmado: o token
   foi gerado e usado mesmo com esses bloqueados) — não vale a pena liberar:
   `static.cloudflareinsights.com` (beacon do próprio Cloudflare, nada a ver com
   MP), `api.mercadolibre.com/tracks` (telemetria do SDK) e um **terceiro** hash de
   script inline que apareceu na 3ª rodada (`sha256-s8pYi5xWVbMRlGKi1UbgBoNVKY7Vq1k+L1GQCPKclW4=`,
   não adicionado). Se algum dia isso importar, o DevTools mostra o hash exato de
   novo.
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
7. **CPF obrigatório trava cliente estrangeiro — verificar depois (pedido em
   2026-09-30).** Hoje `BillingService.startPixCheckout` e o
   `CardCheckoutPanel`/`PixCheckoutPanel` do Frontend (`App.tsx`) exigem CPF
   pra qualquer checkout, cartão ou Pix — sem alternativa pra quem não tem CPF
   brasileiro. Não é um bug isolado: é o mesmo ponto já registrado na seção 3.4 do
   handoff de 08/24 (`docs/HANDOFF-2026-09-13.md`), "Bloco D — pagamento
   internacional", adiado de propósito porque o MP exige `identification.type`
   pra qualquer pagador no Brasil — não dá pra simplesmente tornar opcional sem o
   MP recusar a transação. Decisão de produto em aberto: manter adiado (cliente de
   fora paga em BRL do jeito que dá) ou migrar pra Merchant of Record/gateway
   próprio pra pagador estrangeiro. Só revisitar quando houver sinal real de
   cliente de fora tentando pagar e travando nisso.
8. ~~**Texto do Secure Fields (número/validade/CVV) ilegível no tema escuro**~~ ✅
   **corrigido em 2026-09-30**, em `CardCheckoutPanel` (`App.tsx`). Achado real: a
   documentação e a tipagem da comunidade (`@types/mercadopago-sdk-js`) dizem que
   `style` só existe em `Field.update()`, chamado depois do evento `"ready"` — **isso
   não funciona de verdade**. Testado ao vivo injetando campos de teste via console
   no SDK de produção: `update({style})` pós-`ready` não aplica nada (cor
   continuava a padrão do MP, preta — só "certa" por acidente no tema claro, porque
   preto em fundo claro tem contraste). O que funciona é passar `style` **direto**
   nas opções de `fields.create(field, { placeholder, style })`. Ver
   `secureFieldStyle()` em `App.tsx`.
9. **`getSubscription`/`cancelSubscription` sempre pegam a assinatura mais recente
   por `createdAt` — um Pix não pago gerado depois de um pago "esconde" o pago.**
   Achado testando o fluxo Pix de verdade em 2026-09-30: paguei um Pix, o webhook
   ainda não tinha confirmado (por outro motivo, ver item 2), gerei um SEGUNDO Pix
   pra testar de novo sem pagar, e `GET /billing/subscription` passou a devolver
   o segundo (não pago) em vez do primeiro (pago). Isso não é hipotético — aconteceu
   de verdade nesta sessão. Não chega a ser crítico pro uso normal (cliente comum
   não fica gerando Pix repetido sem pagar), mas é uma janela real: qualquer
   PENDING novo criado depois de um pago-mas-ainda-não-confirmado torna esse pago
   invisível pro app até o webhook processar (e se o webhook nunca processar por
   outro motivo, fica invisível pra sempre). Não corrigido ainda — possíveis
   caminhos: cancelar/expirar o PENDING anterior ao criar um novo, ou
   `getSubscription` preferir o mais recente **AUTHORIZED**, caindo pro mais
   recente qualquer só se não houver nenhum autorizado.

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
1. 🟡 **Teste de integração real com o MP** — `createPixPayment`/`getPayment`
   confirmados batendo com o formato real de resposta em produção, com dinheiro de
   verdade, em 2026-09-30 (ver item 2 da seção 2). Falta ainda
   `createPreapprovalWithCard` autorizando de verdade (só foi testado o caminho de
   rejeição) — precisa do par `TEST-` em sandbox, ou um cartão real.
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

Public key, CSP e **Pix de ponta a ponta** ✅ feitos e confirmados em produção com
dinheiro real em 2026-09-30 — ver seção 2. O que sobrou:

1. Cartão ainda falta autorizar de verdade (só foi testado o caminho de rejeição
   com o cartão de teste público do MP, que produção recusa de propósito) —
   precisa do par `TEST-` (aba "Credenciais de teste" do painel MP) pra sandbox,
   ou um cartão real de alguém.
2. Item 9 da seção 2 — `getSubscription` pega sempre a assinatura mais recente por
   `createdAt`, não a mais recente **autorizada**. Vale corrigir antes de qualquer
   outro teste de Pix, porque foi o que causou confusão real nesta sessão (Pix
   pago "sumiu" atrás de um Pix não-pago gerado depois).
3. Decidir: continuar fechando o recurso de pagamento (item 7 da seção 2 — CPF
   pra cliente estrangeiro) ou migrar o foco pro `cyberaudit-qa` de verdade,
   usando os casos PAY-* como primeiro conteúdo real do projeto de QA.
