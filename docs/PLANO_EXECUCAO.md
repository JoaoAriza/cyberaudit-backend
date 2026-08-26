# Plano de execução — escopo de 2026-08-23

Deriva de [PROXIMOS_PASSOS.md](PROXIMOS_PASSOS.md), com o código verificado em
2026-08-23. Cada **Etapa** é um commit fechado e funcional; etapas de repositórios
diferentes (`Backend` / `Frontend`) são commits separados por definição.

Numeração continua da Etapa 27 (`92e28fd`, já commitada).

---

## Etapa 0 — Operacional, sem commit (fazer antes de tudo)

Nada aqui toca código, mas dois itens têm prazo e um bloqueia deploy.

| # | ação | por quê |
|---|---|---|
| 0.1 | **Backup + upgrade do Postgres do Render** | plano gratuito expira ~30 dias após a criação (criada ~12/08 → vence ~11/09). Sem isso os dados somem |
| 0.2 | Rodar `deploy/audit-action-check.sql` | o enum `audit_logs.action` não é atualizado pelo `ddl-auto`; sem rodar, a redefinição de senha quebra na gravação do log |
| 0.3 | Rodar `deploy/cleanup-free-domains.sql` | domínios de contas FREE ainda na base, de antes do gating |
| 0.4 | `MP_ACCESS_TOKEN` de volta para produção | conferir a linha `[MercadoPago]` no boot, que informa o ambiente |

---

## Bloco A — Cardápio de planos (requisito 1)

### Etapa 28 — Frontend: corrigir o conteúdo do cardápio

`Frontend/src/App.tsx:1352` (`PLAN_DEFS`). Hoje lista seis itens; faltam quatro
diferenças que já valem em produção, e duas linhas estão erradas.

**Adicionar:**

| linha | FREE | PRO | EMPRESA | fonte |
|---|---|---|---|---|
| Detalhe do achado (impacto, correção, breakdown) | ✗ | ✓ | ✓ | `ScanEntitlementService` |
| Agendamentos | ✗ | 10 | ilimitado | `Plan.scheduledScanLimit` |
| Cadastro de domínio | ✗ | ✓ | ✓ | `Plan.domainRegistrationAllowed` |
| Relatórios da conta (auditoria, PDF executivo, status público) | ✗ | ✓ | ✓ | `Plan.reportsModuleAllowed` |

**Corrigir:**

- **"Exportar PDF"** está ✓ nos três e é ambíguo. Desmembrar em
  **"PDF do scan"** (✓ nos três — `Plan.pdfExportAllowed` é `true` até no FREE) e
  **"PDF executivo"** (✗ / ✓ / ✓ — vive em `reportsModuleAllowed`).
- **"Multi-usuário"** está ✗/✗/✓, o que sugere que custa R$ 99,90. **Não é
  verdade:** `InviteService:38` libera convites por `AccountType.COMPANY`, não por
  plano — uma conta Empresa no FREE já convida usuários. Ou muda o rótulo para
  algo como "Conta Empresa (equipe, 2FA obrigatório)" marcado como característica
  do tipo de conta, ou some da lista de diferenças de plano.

*Prioridade máxima do bloco:* o detalhe do achado é o principal diferencial pago e
hoje o FREE vê cadeado sem que a tela de planos explique o que ele compra.

> `feat: cardapio de planos reflete os recursos que existem hoje`

**Feito em 2026-08-23.** Além do previsto, a etapa levou junto uma consequência
direta: com o cardápio indo de seis para nove linhas, as três colunas fixas do
`plansGrid` davam ~145px por card no celular e picavam os rótulos. Adicionada
media query que empilha os cards abaixo de 720px.

### Etapa 28.1 — Frontend: conta Empresa no FREE não conseguia assinar

Achado durante a Etapa 28; é do Bloco B por natureza, mas vive no mesmo modal.

`PlansModal` deriva o plano atual do **tipo da conta**, não do plano
(`App.tsx:1401`): `type === "COMPANY"` já marca o card Empresa como atual. Só que
`AuthService:208` registra **toda** conta em `Plan.FREE`, inclusive COMPANY. O
resultado numa conta Empresa recém-criada:

- o card Empresa de R$ 99,90 aparece com o selo **"Seu plano atual"**
- o botão de assinar é escondido pelo guard `!current` — **a empresa não tem como
  assinar o plano Empresa**
- e o cardápio mente sobre o que ela tem hoje, que é FREE

Correção: derivar de `account.plan` (`ENTERPRISE` → Empresa, `PRO` → Pessoal Pro,
resto → Free). O tipo da conta continua valendo para CNPJ e equipe, não para plano.

> `fix: conta empresa no plano free nao conseguia assinar o plano empresa`

**Feito em 2026-08-23, commitada junto com a Etapa 31** — é a mesma função e a
mesma tela.

### Etapa 29 — Backend: `GET /billing/plans` derivado do enum

Elimina a duplicação que causou a Etapa 28. **Correção ao escopo original:** o doc
sugeria derivar do `AccountDto`, mas o `AccountDto` descreve *uma* conta — o
cardápio precisa dos três planos. O lugar certo é um endpoint público montado a
partir de `Plan.java`.

- `PlanCatalogDto` (chave, nome, preço, moeda, matriz de recursos)
- Preço vindo de `billing.pro.amount` / `billing.enterprise.amount`
  (`BillingService:35-36`) — hoje o Frontend tem `R$ 29,90` e `R$ 99,90` chumbados,
  e mudar o valor no Render **não reflete na tela**
- Endpoint público (o cardápio aparece para visitante)
- Tratar os dois casos que não saem direto do enum: o ◑ de Active Scan
  (`activeScanOnVerifiedOnly`, que depende do tipo da conta) e a linha de
  multi-usuário, que é `AccountType`
- Teste de que a matriz bate com o enum

> `feat: catalogo de planos vem do backend em vez de lista paralela`

**Feita em 2026-08-24.** 211 testes.

**O backend manda estado, não texto.** Cada recurso sai como `id` + `state`
(`YES` / `NO` / `VERIFIED_DOMAINS_ONLY`) + `limit` numérico quando é quantidade. O
rótulo continua no Frontend, indexado pelo id. O que fez o cardápio mentir foi a
matriz de ligado/desligado estar duplicada, não a redação — e mover cópia de
marketing para Java só criaria outro lugar para envelhecer, que a Etapa 36 teria de
desfazer.

`VERIFIED_DOMAINS_ONLY` em vez de um `PARTIAL` genérico: o Frontend desenha ◑ nos
dois casos, mas o estado diz *por quê*, e é isso que permite escrever rótulos
diferentes por card sem consultar outra regra.

**Uma duplicação a menos, de brinde:** `PRO && !empresa` estava escrito em
`AccountDto` e `PlanLimitService`, e o catálogo seria a terceira cópia. Virou
`Plan.verifiedDomainOnly(boolean)`, e os três passaram a chamá-la.

**O teste que importa** é `todaTravaDePlanoApareceNoCardapio`: varre os booleanos
públicos de `Plan` por reflexão e falha quando alguém adiciona trava nova sem
linha no catálogo. Sem ele, o catálogo vindo do enum só muda ONDE a lista
envelhece. O mapa de campo→chave é explícito de propósito — derivar por convenção
de nome esconderia justamente o campo esquecido.

`GET /billing/plans` precisou de exceção no `SecurityConfig`: mora sob
`/billing/**`, que é `.authenticated()`. Coberto pelo teste de cadeia da Etapa 40 —
sem isso a tela de planos ficaria invisível para o visitante, que é justamente o
público que ela existe para converter.

### Etapa 30 — Frontend: consumir `/billing/plans`

Remove `PLAN_DEFS`; `PlansModal` renderiza o que o backend mandar. Fallback para a
lista atual se a chamada falhar (o modal não pode ficar vazio).

> `refactor: modal de planos monta o cardapio a partir da api`

**Feita em 2026-08-24.** `PLAN_DEFS` saiu; o modal renderiza o que a API mandar.
O que ficou no Frontend é só redação: nome e documento do card, a nota da Empresa e
o rótulo de cada `id` de recurso.

**Mudei uma decisão do próprio plano: não há lista de reserva.** A etapa previa
"fallback para a lista atual se a chamada falhar", e isso está errado — a lista de
reserva **é** a lista paralela que envelhece, e ela mentiria justamente quando a API
estivesse fora, mostrando preço velho como se fosse o atual. Falhar em voz alta
("Não foi possível carregar os planos" + "Tentar de novo", zero cards) é melhor que
mentir baixinho numa tela que vende.

**O laço fechou nas duas pontas:** o teste de reflexão da Etapa 29 quebra o build se
alguém adicionar trava em `Plan.java` sem chave no catálogo; e rótulo faltando no
Frontend renderiza o **id cru** na tela, em vez de omitir a linha. Nenhuma das duas
falhas é silenciosa — omissão silenciosa foi o problema original.

Verificado com a API stubada: saída idêntica à da lista estática, incluindo
"Relatórios da equipe" na Empresa e a nota do card. Preço agora sai de
`Intl.NumberFormat` sobre o `amount` da API — mudar `BILLING_PRO_AMOUNT` no
ambiente passa a refletir na tela.

---

## Bloco B — "Seu plano atual" sincronizado (requisito 2)

Verificado: **funciona** no retorno do checkout (`BillingReturnPage` faz polling e
recarrega a página). As lacunas são reais.

### Etapa 31 — Frontend: `refreshUser()` no AuthContext

`AuthContext.tsx` expõe `login/register/verify2fa/resendEmailOtp/logout` e nada que
refaça `/auth/me` (`AuthContext.tsx:58-72`). Adicionar `refreshUser()` ao contexto e
chamá-lo ao abrir o `PlansModal` — resolve tanto o cancelamento quanto a conta
rebaixada por webhook enquanto o usuário está logado.

> `fix: plano atual se atualiza sem precisar recarregar a pagina`

**Feito em 2026-08-23**, junto com a Etapa 28.1. `refreshUser` é `useCallback` com
deps vazias de propósito: a referência é dependência do efeito de quem chama, e sem
isso o efeito rearma a cada render do provider e vira laço. Falha de rede não
derruba a sessão — só 401 faz isso, pelo interceptor.

### Etapa 32 — Frontend: tela de cancelamento (lacuna nova, não estava no escopo)

**`POST /billing/cancel` existe no backend (`BillingController:88`) e nenhuma tela
o chama.** Um assinante não tem como cancelar pelo produto. Adicionar no
`PlansModal`, sobre o card do plano atual: botão de cancelar, confirmação, e
`refreshUser()` no sucesso.

> `feat: assinante cancela o plano pela tela de planos`

**Feita em 2026-08-24.** Botão no card do plano atual, só quando ele é pago —
`current && planoDaApi(plan.key)`. Confirmação por `confirm()`, que é o idioma do
resto do arquivo para ação destrutiva.

**O texto avisa que o corte é imediato porque é o que o código faz:**
`BillingService.cancelSubscription` grava `CANCELLED` e rebaixa a conta para FREE
na mesma transação — **não há carência até o fim do período já pago**. Quem cancela
no dia 2 perde o mês inteiro que pagou. É decisão de produto em aberto: o padrão de
mercado é manter o acesso até o fim do ciclo, e mudar isso exigiria guardar a data
de expiração e só rebaixar quando ela chegar.

---

## Bloco C — Internacionalização (requisito 3)

Ordem obrigatória: **catálogo antes de interface.** O conteúdo do laudo é gerado no
backend em português; traduzir só a casca deixa o cliente lendo interface em inglês
e achado em português.

**Boa notícia da verificação:** o conteúdo está mais concentrado do que o escopo
supunha. Todo `SecurityIssue` nasce em **um único arquivo** —
`ScoreService.java` (779 linhas, 36 construções, ~25 IDs estáveis como
`HSTS_MISSING`, `DNS_EMAIL_SPOOFING`, `CSP_MISSING`). É um catálogo de tamanho
tratável, não uma varredura pelo backend inteiro.

### Etapa 33 — Backend: catálogo de mensagens indexado por ID

`messages_pt-BR.properties` com `issue.<ID>.title|impact|recommendation`.
`ScoreService` passa a resolver pelo catálogo. **Contrato da API não muda** — ainda
devolve texto pronto, agora vindo de um arquivo. Commit sem risco de regressão
visível, e o teste é comparar a saída antes/depois.

> `refactor: textos dos achados saem do codigo para catalogo por id`

**Feita em 2026-08-24.** 218 testes. `messages.properties` (pt-BR, também o
fallback) + `IssueCatalog` sobre o `MessageSource` do Spring. `ScoreService` foi de
779 para 705 linhas; 29 dos 36 achados viraram uma linha só, pelo helper
`achado(chave, severidade, argsDoTítulo...)`.

**Contrato da API não mudou** — a resposta continua trazendo texto pronto, agora
lido de arquivo. O locale já sai do `LocaleContextHolder`, que hoje devolve sempre
o padrão: o ponto de virada fica pronto para a Etapa 34 sem tocar em lógica de scan.

**O catálogo cobre o que o ScoreService escreve, não tudo que aparece no laudo.**
Cinco achados têm impacto vindo de outro serviço — `DnsSecurityService.getSummary()`,
`HttpMethodService.getRisk()`, `JwtSecurityService`, `ApiDocsExposureService` — e o
CVE traz a descrição do NVD, que nasce em inglês e não tem o que traduzir do nosso
lado. Esses continuam repassando o texto de origem, e são superfície de tradução
que a Etapa 34 **não** resolve.

`spring.messages.fallback-to-system-locale=false` no `application.properties`: sem
isso, locale desconhecido cairia no locale do SERVIDOR antes do arquivo padrão, e o
resultado mudaria conforme a máquina onde roda.

**Cuidado que já custou um teste:** mensagem com parâmetro passa por
`MessageFormat`, onde `'` é escape. O título do JWT tem aspas e precisou de `''`.
Mensagem sem parâmetro não passa, e aspa simples funciona — daí `Let's Encrypt` com
uma só. `IssueCatalogTest` trava os dois casos.

### Etapa 33.1 — Notas do breakdown para o catálogo

Ficaram de fora e são visíveis: 46 `notes.add(...)` no `ScoreService`, em português
("HTTPS não suportado: -40"). É o breakdown do score, que o PRO vê. **Sem esta
etapa, a 34 entrega laudo em inglês com breakdown em português** — exatamente o
meio-caminho que a ordem do bloco existe para evitar.

Mesmo mecanismo, chave `note.<ID>`. Separada só para não misturar dois assuntos num
commit.

> `refactor: notas do breakdown saem do codigo para o catalogo`

**Feita em 2026-08-24.** 221 testes. As 46 notas viraram 48 chaves `note.<ID>`
(duas a mais porque o GraphQL tem variante para playground e introspection, e o WAF
tem um fragmento condicional). **Nenhum texto de usuário sobrou no `ScoreService`**
— o que resta em português ali é comentário de código.

Prefixo `note.` separado de `issue.` porque são famílias diferentes: o achado
descreve o problema, a nota justifica o desconto. Existe nota sem achado (o "OK" do
SSL, o bônus de WAF) e achado sem nota, então as duas listas não coincidem.

O número do desconto é parâmetro quando o código o calcula, e fica no texto quando
é constante — assim o tradutor lê a frase inteira e o valor não se perde. Um teste
compara amostras exatas com o texto de antes, porque perder o "-40" quebraria o
breakdown sem quebrar nada visível.

**O Bloco C está pronto para a Etapa 34 do lado do laudo.** O que continua fora do
catálogo, e a 34 não resolve: os impactos que vêm de `DnsSecurityService`,
`HttpMethodService`, `JwtSecurityService`, `ApiDocsExposureService` e do NVD.

### Etapa 34 — Backend: negociação de idioma + inglês

`Accept-Language` (ou `?lang=`) resolvido para o `Locale`, `messages_en.properties`,
fallback para pt-BR quando faltar chave.

> `feat: api entrega os achados no idioma pedido`

**Feita em 2026-08-24.** 229 testes. `messages_en.properties` com as ~130 chaves, e
`LocaleConfig` resolvendo `?lang=` antes do `Accept-Language` — quem troca o idioma
na tela está justamente dizendo que não quer o do navegador.

**Dois defeitos apareceram ao ligar a tradução, e não eram óbvios no papel:**

1. **O scan assíncrono sairia sempre em português.** `LocaleContextHolder` é
   ThreadLocal e `executeAsync` roda em outra thread — e é esse o caminho que a
   interface usa. O idioma passou a ser capturado na thread da requisição, em
   `submit`, e reinstalado na thread do scan, com `finally` para limpar: a thread
   volta ao pool e serviria o próximo scan com o idioma errado.

2. **O cache devolveria o idioma de quem chegou primeiro.** A chave era
   `host + active`, e o resultado guardado já traz o TEXTO montado — dentro dos 2
   minutos de TTL, um scan feito em português voltaria para quem pediu inglês. O
   idioma entrou na chave. Custa refazer o scan uma vez por idioma no mesmo host
   dentro da janela; o conserto sem esse custo é o resultado guardar ID +
   parâmetros e o texto ser montado na saída — mudança de contrato, grande, e que
   esta etapa não faz.

**A tradução é fallback-tolerante, e é por isso que precisa de teste.** Chave que
falta no inglês resolve para o português: nada quebra, e o laudo sai metade em cada
idioma parecendo funcionar. `IssueCatalogEnglishTest` compara os dois arquivos nas
duas direções — chave sem tradução, e chave que só existe no inglês (erro de
digitação).

### Etapa 35 — Backend: PDF e e-mails no idioma da conta

`PdfReportService`, `ExecutivePdfReportService` e os templates de e-mail. Sem isso o
cliente estrangeiro recebe tela em inglês e laudo em português — exatamente o que a
ordem deste bloco existe para evitar.

> `feat: pdf e emails seguem o idioma da conta`

**Dividida: a 35 fez os e-mails; os PDFs viraram a 35.1.** São 2.300 linhas em
`PdfReportService`, `ExecutivePdfReportService` e `ReportService` — não cabe no
mesmo commit dos e-mails sem virar um diff impossível de revisar.

### Etapa 35.1 — o levantamento mudou o que a etapa é

Levantado em 2026-08-24, **antes de tocar em código**. Os três artefatos de
relatório estão em três estados diferentes, e nenhum é sensível a idioma:

| artefato | estado hoje | quem recebe |
|---|---|---|
| `PdfReportService` — PDF do scan | **100% em inglês** | é o PDF que o cliente exporta |
| `ExecutivePdfReportService` — PDF executivo | **100% em português** (sem acentos) | PRO+ |
| `ReportService` — relatório texto | inglês, com **9 frases soltas em português** | `/scan/report` |

Ou seja: a etapa **não é** "traduzir os PDFs para inglês". O PDF do scan já é
inglês — e é o **cliente brasileiro** que recebe documento em idioma que não pediu.
O executivo é o inverso. O relatório texto é misto.

São ~110 strings, e a maior parte do trabalho é escrever a versão **em português**
do PDF principal, que é copy de produto do mercado primário.

**Decidido em 2026-08-24: os três relatórios ficam em inglês, monolíngues.** A
escolha de idioma vale para o site; o documento exportável, não. É o arquivo que o
cliente encaminha para auditor, compliance ou cliente dele, e um PDF que muda de
idioma conforme quem clicou "exportar" atrapalha justamente esse uso.

**Feita em 2026-08-24.** 233 testes. `ExecutivePdfReportService` traduzido (~30
rótulos) e as 9 frases órfãs do `ReportService` também. `PdfReportService` não
mudou uma linha: já era inglês.

**Sem catálogo, de propósito** — pôr esses textos no `MessageCatalog` sugeriria que
são traduzíveis, que é o oposto da decisão. O motivo ficou em comentário no topo
das três classes, com a instrução "ao adicionar texto aqui: escreva em inglês", que
é onde quem for mexer vai ler.

**Efeito colateral bom:** o PDF executivo estava escrito sem acento ("Relatorio
Executivo de Seguranca", "Periodo", "Dominios") por limitação de fonte do PDFBox. Em
inglês o problema deixa de existir.

**Consequência conhecida, registrada no código:** o TEXTO DOS ACHADOS dentro dos
documentos vem do `ScanResult`, montado no idioma da requisição. Um cliente
navegando em português exporta PDF com moldura em inglês e achados em português —
como sempre foi, e agora um cliente em inglês recebe o documento inteiro coerente.
Deixar tudo em inglês exigiria o resultado guardar ID + parâmetros em vez de texto
pronto: a mesma mudança de contrato que a Etapa 34 já apontou no cache.

**Etapa 35 — e-mails — feita em 2026-08-24.** 233 testes. Os cinco templates
(scan concluído, degradação, código 2FA, redefinição de senha, feedback) leem
assunto e prosa do catálogo, com 45 chaves nos dois idiomas.

**A estrutura HTML ficou no `EmailService`, não no catálogo.** Marcação em arquivo
de mensagens não é traduzível na prática — o tradutor teria de mexer em tags — e
sai do controle de versão do código, onde ela pertence.

**Frase inteira, nunca picada.** A saudação recebe o nome já estilizado como
parâmetro em vez de ser montada com `"Olá, " + nome`: a ordem das palavras muda de
idioma para idioma, e frase concatenada não sobrevive à tradução.

**`IssueCatalog` virou `MessageCatalog`.** Com texto de e-mail dentro, o nome
deixou de ser verdade.

**O agendamento ganhou coluna `locale`.** É o único caminho que roda sem requisição
HTTP: não há `Accept-Language` para consultar na hora de executar, então o idioma
de quem criou fica gravado na linha. Nulo nos agendamentos antigos, que caem no
padrão — exatamente o que já recebiam.

**Achado de passagem:** o bloco de findings do e-mail de scan é ARGUMENTO do
`formatted`, não o template, e tinha `width='100%%'` — o `%%` saía literal no HTML.
Corrigido.

Os testes agora **renderizam os cinco templates de ponta a ponta**, com um
transporte de mentira que captura assunto e corpo. O de degradação tem 21
argumentos posicionais: errar a ordem não é erro de compilação, e sem renderizar
ninguém veria.

### Etapa 36 — Frontend: extração das strings + seletor de idioma

O maior item do plano: **`App.tsx` tem 6.950 linhas** com as strings inline. Cabe
quebrar em mais de um commit (extração por tela). Seletor no header, preferência
persistida, `Accept-Language` no cliente da API.

> `feat: interface traduzida e seletor de idioma`

### Levantamento (2026-08-24, antes de tocar em código)

**~700 strings reais** de interface, em 53 componentes. (Extraí 831; cerca de 15%
são falso-positivo do meu filtro — `_blank`, `repeat(4, 1fr)`, nomes de host.)

Concentração: `App` 149 · `AdminPanel` 66 · `ActiveChecksPanel` 63 · `SetupPage` 49
· `IntradayChart` 48 · `SchedulesPage` 46 · `LoginPage` 41 · `SettingsPage` 33.
Cauda de 202 strings espalhadas por 33 componentes. Só ~25 strings aparecem em mais
de um componente, então o vocabulário compartilhado é pequeno e quase tudo é local.

**Quatro coisas que o plano não previa:**

1. **`Accept-Language` não está no CORS.** `CorsConfig` lista
   `Authorization, Content-Type, X-Api-Key, Accept` e mais nada. Se o Frontend
   começar a mandar o header antes de o backend liberar, o preflight recusa — a
   mesma classe do bug que a Etapa 40 existe para pegar. **O backend tem de subir
   primeiro**, e cabe um caso novo no `SecurityChainIntegrationTest`.

2. **18 `pt-BR` chumbados** em `toLocaleDateString`/`toLocaleString`/`toLocaleTimeString`.
   Data e hora não são texto e não estavam no escopo, mas um cliente em inglês
   veria `24/08/2026 14:30` em vez de `8/24/2026 2:30 PM`.

3. **`TermsModal` contém os Termos de Uso e a Política de Privacidade.** Isso é
   documento jurídico, não copy de produto. A política responde à LGPD, e uma
   versão em inglês passaria a valer para quem a lê em inglês. **Recomendo deixar
   fora do escopo** e manter em português, ou contratar tradução jurídica.

4. **Não há biblioteca de i18n no projeto.** Recomendo `t()` própria, espelhando o
   catálogo do backend: mesma forma de chave, mesmos `{0}`. Sem dependência nova, e
   consistente com o resto do Frontend, que não usa router nem state library — o
   `AuthContext` é feito à mão pelo mesmo motivo. Com dois idiomas e interpolação
   simples, `react-i18next` cobraria configuração e bundle sem resolver nada que já
   não esteja resolvido.

### Divisão proposta — 7 commits

| # | escopo | strings |
|---|---|---|
| **36.0** | *Backend*: `Accept-Language` no CORS + caso no teste de cadeia — **feita** | — |
| **36.1** | Infraestrutura: `I18nContext`, `t()`, os dois catálogos, seletor no header, persistência, header no cliente axios — **feita** | ~10 |
| **36.2** | Entrada: Login, Setup, Esqueci/Redefinir senha, AcceptInvite — **feita** | ~120 |
| **36.3a** | Scanner — casca: header, painel de scan, barra lateral, painel de resultado — **feita** | ~110 |
| **36.3b** | Scanner — cards de módulo (Transport, DNS, Cookie, Tech, CVE, Header) — **feita** | ~120 |
| **36.3c** | Scanner — `ActiveChecksPanel`, `CompliancePanel` e os componentes de bloqueio/visitante — **feita** | ~100 |
| **36.4** | Conta: Settings, ApiKeys, Branding, Domains, Schedules — **feita** | ~150 |
| **36.5** | Admin e relatórios: AdminPanel, AuditLogs, Changes, gráficos, feedback, status público — **feita** | ~150 |
| **36.6** | Datas e números seguem o idioma ativo — **feita** | 19 pontos |
| **36.7** | Modal de planos, `MODULE_INFO` e as últimas sobras — descoberta pela varredura final | ~100 |

A 36.0 e a 36.1 destravam o resto; da 36.2 em diante a ordem é livre, e cada uma
deixa a aplicação funcionando com parte traduzida — chave sem tradução cai no
português, igual ao backend.

**Decidido em 2026-08-24:** `t()` própria, sem biblioteca. E os Termos de Uso e a
Política de Privacidade **ficam em português**, fora do escopo de tradução — são
documento jurídico, não copy de produto.

**Etapa 36.0 feita em 2026-08-24.** 235 testes. Dois testes cobrem o header: um de
unidade sobre a allowlist e um de cadeia que faz o preflight pedindo
`authorization,accept-language` junto. Conferi que os dois **falham** se o header
sair da lista — teste que nunca ficou vermelho não protege nada.

**Este commit tem de estar em produção antes da Etapa 36.1.** É ele que permite ao
Frontend mandar o header; na ordem inversa, o preflight recusa e a API para de
responder para o navegador.

### Etapa 36.1 — feita em 2026-08-24

`src/i18n/catalog.ts` (idiomas, preferência, `traduzir`) e `src/i18n/I18nContext.tsx`
(provider, `t()`). Seletor PT/EN no header, ao lado do tema.

**O interceptor manda `Accept-Language` explícito, com o idioma da TELA.** Sem
isso o Backend decidiria pelo `Accept-Language` do navegador, e a interface em
português entregaria laudo em inglês para quem tem o navegador em inglês — o
descasamento que a Etapa 34 abriu. Agora os dois lados sempre concordam.

**A preferência mora no `catalog.ts`, não no contexto React.** Quem mais precisa
dela é o cliente HTTP, que vive fora do React e lê a cada requisição, do mesmo
jeito que já lê o token. Uma cópia em memória sincronizada com o provider daria
duas fontes para a mesma verdade, e elas divergiriam na primeira aba aberta em
paralelo. De quebra, tira o import de um módulo `.ts` para um `.tsx` de componente.

**Trocar o idioma recarrega a página, de propósito.** O resultado de scan já na
tela veio do Backend no idioma anterior; re-renderizar só a moldura deixaria metade
em cada idioma — o meio-termo que este bloco inteiro existe para evitar.

**Seletor visível para visitante**, não só para quem tem conta: a tela de planos e
o scan público são o que o cliente estrangeiro vê antes de se cadastrar.

Verificado no navegador: seletor troca, preferência persiste, `document.lang`
acompanha, e o header sai `en` ou `pt-BR` conforme a escolha — **contrariando o
navegador**, que está em pt-BR, que é justamente o comportamento desejado.

### Etapa 36.2 — feita em 2026-08-24

Login, cadastro, 2FA, esqueci/redefinir senha, configuração inicial e aceitar
convite. ~120 chaves nos dois idiomas.

**Bug encontrado ao navegar em inglês: o seletor não existia em nenhuma dessas
telas.** Todas retornam antes do header, e era lá que o seletor morava — ou seja,
justamente as primeiras telas que um estrangeiro vê não tinham como trocar de
idioma. Entrou uma variante `flutuante` (fixa no canto superior direito) em login,
setup, convite, redefinição de senha e página de status pública.

**Frase com link não é picada.** "Li e aceito os {0} e a {1}" chega inteira ao
tradutor: em inglês a ordem e as preposições mudam. `fraseComLinks` parte a frase
JÁ TRADUZIDA nos marcadores e encaixa os elementos — concatenar pedaços travaria a
frase na gramática do português.

**Um sed com `/g` alcançou o formulário de convite do `AdminPanel`**, que é da
Etapa 36.5. Revertido para o commit não vazar de escopo.

Navegação verificada em inglês, tela por tela: login, cadastro (incluindo a frase
dos termos), esqueci a senha, redefinição por link e aceitar convite. A troca de
idioma a partir de uma tela sem header **preserva a URL**, inclusive o token do
convite. `SetupPage` não deu para abrir no navegador — depende de o Backend
responder que não há usuários — e ficou verificada só por leitura.

### Etapa 36.3a — feita em 2026-08-24

Header, navegação, painel de scan, barra lateral de módulos e painel de resultado.
Catálogo em **192 chaves nos dois idiomas, sem lacuna**.

**Bug encontrado e corrigido: sombra da função `t`.** No painel de Subdomain
Takeover o callback do `map` se chamava `t` — `(t: any, i: number) => …` — e as
chamadas `t("col.subdominio")` que o sed inseriu ali passariam a chamar o OBJETO do
achado. O tipo `any` esconde do TypeScript, e o resultado seria
`t is not a function` em runtime, derrubando o painel **sempre que houvesse um
achado de takeover**. Compilava e passava despercebido porque o painel só renderiza
com achado. Parâmetro renomeado para `tk`, e verificado no navegador com um achado
de takeover no stub.

**Resta uma sombra igual em `FindingCardsPanel`** (`extraTags?.map((t, i)`), hoje
inofensiva porque aquele componente ainda não usa `t()`. **A Etapa 36.3b tem de
renomeá-la antes de inserir qualquer tradução ali.**

**Nem toda string do arquivo é traduzível.** Cerca de 25 são trechos usados para
CASAR mensagem de erro do Backend — `"UnknownHostException"`, `"connect timed out"`,
`"proprietário verificado"`. Traduzir aquilo quebraria o reconhecimento do erro em
silêncio. Ficaram como literais.

Um `sed` global alcançou `SchedulesPage`, `ChangesPage`, `DomainsPage` e
`PublicStatusPage`, de etapas seguintes — revertido, para não deixar componente com
três strings traduzidas e quarenta em português.

**Ainda não há guarda automática de paridade no Frontend.** Conferi com script
avulso (192/192). O Backend tem teste para isso; o Frontend não tem nenhum teste, e
montar um runner só para essa checagem é decisão à parte.

### Etapa 36.3b — feita em 2026-08-24

Cards de Transport, DNS, Cookie, Technology, CVE e Headers. Catálogo em **273
chaves nos dois idiomas, sem lacuna**; 255 chaves em uso, nenhuma ausente.

**A sombra do `t` em `FindingCardsPanel` foi renomeada primeiro**, como a 36.3a
tinha registrado — antes de qualquer tradução entrar naquele componente.

**Segunda armadilha do mesmo tipo, e mais interessante: `TECH_RISK`.** É uma tabela
no nível do MÓDULO, fora de qualquer componente, com descrição e texto de risco de
cada tecnologia. Fora de componente não existe `t()`, e o `sed` tinha inserido
chamadas ali — não compilava. A tabela passou a guardar **chaves de catálogo**
(`descKey`/`riskKey`) e quem renderiza resolve. É o padrão para qualquer tabela de
módulo com texto, e vale para as etapas seguintes.

Verificado no navegador em inglês, com scan stubado: Transport (protocolo fraco,
certificado, dias restantes), Technology (descrições vindas da tabela de chaves) e
o estado vazio de Cookies. Duas sobras apareceram nessa navegação — o status
"FRACO" e o rodapé "clique para ver detalhes" do `ModCard` — e foram corrigidas.

### Etapa 36.3c — feita em 2026-08-24

`ActiveChecksPanel`, `CompliancePanel`, o achado (`IssueItem`), os bloqueios de
plano e os componentes de visitante. Catálogo em **361 chaves nos dois idiomas**;
339 em uso, nenhuma ausente.

**Terceira sombra do `t` — e a última.** Em `CompliancePanel`, o `.map(t => …)`
das abas LGPD/ISO. Desta vez o TypeScript pegou (`Type 'String' has no call
signatures`), porque o tipo era literal e não `any` — mas foi sorte, não desenho.

Depois disso varri o arquivo inteiro atrás de qualquer `t` sombreado e achei mais
dois: `getResetTokenFromUrl` e o filtro de takeover no `App`. Nenhum quebrava
hoje, porque ainda não havia `t()` naqueles escopos — eram armadilhas esperando a
próxima etapa. **Todos renomeados.** Hoje não sobra nenhum `t` sombreado no
arquivo.

**A lição para as etapas 36.4 e 36.5:** `t` é nome de variável curto e comum
demais. Antes de inserir tradução em qualquer componente, vale rodar
`grep -nE '\.map\(\s*\(?t\b'` no arquivo. Uma regra `no-shadow` no eslint
resolveria de vez, mas configurar isso é decisão à parte.

Verificado em inglês com scan stubado: WAF Detection, CORS Analysis e as
descrições longas dos probes. Quatro descrições do `ActiveChecksPanel` tinham
escapado do meu extrator e só apareceram na navegação — corrigidas.

### Etapa 36.4 — feita em 2026-08-24

Agendamentos (lista, formulário e modal de detalhe), Domínios, Configurações de
segurança, API Keys, Identidade Visual e exclusão de conta. Catálogo em **466
chaves nos dois idiomas**; 438 em uso, nenhuma ausente.

Nenhuma sombra de `t` nesta rodada — rodei a checagem antes de começar, como a
36.3c recomendou, e o único acerto era anotação de tipo em interface.

**Estas cinco telas NÃO foram verificadas no navegador.** Todas exigem sessão
autenticada, e o `/auth/me` do boot roda antes de qualquer stub que eu consiga
instalar pelo console — um reload apaga o stub. Ficaram verificadas por varredura
estática: nenhuma string em português restante nos componentes, paridade de
catálogo limpa e `tsc -b` limpo. É verificação mais fraca que a das etapas
anteriores, e vale saber disso ao revisar.

**Continua pendente para a 36.5:** `AUDIT_ACTION_LABELS`, tabela no nível do
módulo com os rótulos do log de auditoria — mesma armadilha do `TECH_RISK`, e a
mesma solução: guardar chaves e resolver na renderização.

### Etapa 36.5 — feita em 2026-08-24

Painel admin, log de auditoria, histórico de mudanças, gráficos, feedback (cliente
e admin), convites, página de status pública e retorno do checkout. Catálogo em
**640 chaves nos dois idiomas**, sem lacuna.

**Duas tabelas de módulo a mais viraram tabelas de chave**, no formato que o
`TECH_RISK` estabeleceu: `AUDIT_ACTION_LABELS` → `AUDIT_ACTION_KEYS`, e o
`HEADER_META` — este com uma decisão a registrar: **`short` e `example` ficaram
literais**. São termo técnico e valor de configuração; traduzir
`default-src 'self'` daria ao cliente um valor que não funciona. O único
"Permissões" que sobrou virou "Permissions", que é a abreviação do próprio nome do
header e já era o padrão dos outros sete.

**Uma função fora de componente também virou função de chave:** `fbStatusLabel` →
`fbStatusKey`. Mesmo princípio — quem renderiza resolve.

Ação de auditoria sem chave cai no próprio código da ação: ação nova no Backend
aparece crua na tela em vez de sumir dela.

**O `sed` quebrou quatro linhas aninhando aspas dentro de chaves JSX** (`"{t(...)}"`)
— todas pegas pelo `tsc` na hora. Duas viraram interpolação de verdade
(`auditoria.semEventos` e `admin.semFeedback` com `{0}`), porque eram frases
partidas em pedaços que não sobreviveriam à tradução.

Verificado no navegador em inglês o que é alcançável sem sessão: retorno do
checkout e página de status pública. O painel admin e o log de auditoria têm a
mesma limitação da 36.4 — exigem sessão, e ficaram só na varredura estática.

### Etapa 36.6 — feita em 2026-08-24

Quatro helpers em `catalog.ts` (`formatarData`, `formatarHora`, `formatarDataHora`,
`formatarMoeda`) substituíram os 19 `pt-BR` chumbados. Leem `idiomaAtual()` a cada
chamada, como o interceptor faz com o token — trocar o idioma recarrega a página,
então não há estado a sincronizar.

**Um ponto ficou fixo em "en" de propósito:** a data na prévia do cabeçalho do PDF,
dentro da Identidade Visual. O PDF é monolíngue em inglês por decisão, e a prévia
tem de bater com o documento, não com a tela. Está comentado na linha.

`precoDoPlano` era função de módulo e passou a receber o `t` como parâmetro — era
onde "Grátis" e "/mês" estavam presos.

### Etapa 36.7 — descoberta pela varredura final

Rodei a varredura no arquivo inteiro depois da 36.6 e sobrou uma superfície que o
levantamento original não previa, porque eu dividi por TELA e estas peças nasceram
antes de haver i18n (etapas 28–32):

- **Modal de planos** — `PLAN_CARDS`, `rotuloDoRecurso`, confirmação de
  cancelamento, "Faça login para assinar", mensagens de erro do checkout. **É a
  tela que vende o produto para o cliente estrangeiro**, e está inteira em
  português.
- **`MODULE_INFO`** — 23 entradas × 3 textos (o que é, o que faz, dica) do modal
  "Saiba mais" de cada módulo. Quarta tabela de módulo do arquivo; mesmo
  tratamento das outras três.
- Duas sobras avulsas: `SidebarNavItem` ("Módulo bloqueado") e um "SERVIÇO" no
  detalhe do scan agendado.

Fora do escopo, corretamente: `TermsModal` (decisão de produto) e o
`"proprietário verificado"` do `App`, que casa mensagem de erro do Backend.

**Decidido em 2026-08-23:** começar por **inglês**, e ampliar o leque depois. O
bloco inteiro está destravado.

Consequência prática: as etapas 33 a 35 devem tratar o idioma como **lista aberta**
desde o primeiro commit — resolver `Locale` de verdade e cair em pt-BR quando faltar
chave, em vez de um `if (inglês)`. Assim o segundo idioma é só mais um
`.properties`, sem revisitar o código. `es` é o candidato natural para o próximo:
mesma região do Mercado Pago.

---

## Bloco D — Pagamento internacional (requisito 4)

**Decidido em 2026-08-23: adiado.** Enquanto o cliente de fora conseguir pagar pelo
fluxo atual, está valendo. Bloco fora do plano de execução — fica registrado como
contexto para quando o assunto voltar.

**O que o código faz hoje, para quando a decisão for retomada:**

- A moeda é **uma só, global**: `billing.currency`, default `BRL`
  (`BillingService:37`). Não há preço por região
- `Account.country` é capturado no cadastro (`RegisterRequest:31`) e **não é usado
  em nada do billing** — o roteamento por país já teria o dado disponível
- Consequência: o cliente estrangeiro é cobrado em reais, com conversão e IOF do
  banco dele, num checkout do MP em português. Funciona se o cartão passar, mas é
  isso que ele vê

**Gatilhos para retomar:** cartão estrangeiro sendo recusado, ou volume de fora que
justifique cobrar em moeda local.

**Quando retomar, a decisão é essa:**

| | exemplo | quem lida com imposto |
|---|---|---|
| Gateway | Stripe | **você** — VAT europeu por país, sales tax americano |
| Merchant of Record | Paddle, Lemon Squeezy, Polar | **eles** — vendem em nome próprio |

Para operação enxuta vendendo software mundo afora, o MoR costuma valer a taxa
maior. Junto: **preço fixo em USD ou preço por região?**

### Etapa 37 — interface `PaymentProvider` — **PARADA junto com o bloco**

Estava no plano como refactor barato para destravar o segundo provedor. Sem segundo
provedor decidido, extrair a interface é indireção que não paga nada hoje: uma
interface com uma implementação só. `BillingService` continua chamando
`MercadoPagoService` direto (`BillingService:33`), e o refactor entra junto com a
Etapa 38, quando existir a segunda implementação para justificar o formato. O
desenho de referência (`EmailSender` → `SmtpEmailSender`/`ResendEmailSender`) já
está no repositório e não vai a lugar nenhum.

### Etapa 38 — Segundo provedor — **ADIADA**

Implementação, webhook próprio, roteamento por país da conta e moeda.

---

## Bloco F — Entrega de relatório: PDF e e-mail

Aberto em 2026-08-23 por um teste do próprio dono: uma conta FREE recebeu por
e-mail os títulos MEDIUM/HIGH que a tela mostrava borrados ao lado.

**Prioridade: à frente de tudo no plano, junto com a Etapa 0.** Este bloco é o que
sustenta a cobrança do produto.

### Etapa 42 — Fechar o vazamento — **FEITA em 2026-08-23**

O gating vivia só no caminho da tela. Três entregas passavam por fora:

| onde | o que entregava |
|---|---|
| `AsyncScanService:100` | e-mail do scan manual, com `result` cru — **é o que o teste pegou** |
| `ScheduledScanService:106` | e-mail do agendamento, também cru |
| `ScanController` `/report/pdf?url=` | PDF do caminho de re-scan, também cru |

O PDF por `scanId` **já estava correto**: lê o status que o `AsyncScanService`
gravou, que é a cópia travada.

Os três passaram a chamar `applyEntitlement` antes de entregar. A regra vale para
qualquer canal, não só para a tela — e continua valendo se a política de plano
mudar depois.

> `sec: email e pdf entregavam o detalhe que a tela esconde no plano free`

### Etapa 43 — Backend: PDF e e-mail viram recurso pago

Decisão do dono em 2026-08-23. Hoje `Plan.FREE.pdfExportAllowed` é `true` e a
notificação por e-mail não tem trava de plano nenhuma.

- `Plan.FREE.pdfExportAllowed` → `false`
- flag nova `emailNotifyAllowed`: `false` no FREE, `true` no PRO e ENTERPRISE
- **Pessoal Pro só exporta/notifica em domínio próprio verificado.** Mesma regra do
  Active Scan (`activeScanOnVerifiedOnly` = `PRO && !isCompany`), e o mecanismo já
  existe: `domainRegistrationAllowed` é PRO+, então o Pro consegue verificar
  domínio. Empresa e ENTERPRISE seguem sem restrição
- `PlanLimitService.checkPdfExport` passa a receber o host; check equivalente para
  o `notify` na submissão do scan e na criação do agendamento

**Consequência a aceitar:** o consultor autônomo que assina o Pro para auditar site
de cliente vê o laudo completo na tela e não consegue exportar. Ou ele sobe para
Empresa, ou se perde. Se a intenção for mantê-lo no Pro, a alternativa é liberar o
PDF em qualquer domínio e limitar por volume em vez de por posse.

> `feat: pdf e notificacao por email viram recurso de plano pago`

**Feita em 2026-08-23.** Regra única em `PlanLimitService.checkReportDelivery`,
usada por `checkPdfExport` e `checkEmailNotify`. Detalhes que valem registro:

- A trava do PDF por `scanId` só roda **depois** de achar o scan — a regra depende
  do host, e o host vem do resultado
- `canEmailNotify` é a variante que não lança, para o agendador: a assinatura pode
  cair entre a criação do agendamento e a rodada, e uma exceção ali mataria as
  notificações dos outros scans da mesma rodada
- `notify` é recusado na **submissão** do scan, não na thread assíncrona — falha lá
  vira scan perdido em vez de mensagem na tela
- Sem check de staff: `effectivePlan(AppUser)` já promove a equipe a ENTERPRISE,
  que não cai na restrição de domínio
- 5 testes novos em `PlanLimitServiceTest` fixam a política (187 no total). O teste
  que afirmava "PDF é liberado para quem loga" foi reescrito — era a política velha

**Sobre a responsabilidade do scan ativo na conta Empresa:** o rastro que sustenta
o "chefe de setor ciente" já existe — `ScanOrchestrator` grava `SCAN_STARTED` e
`SCAN_COMPLETED` no log de auditoria, com modo, URL e score, e o log é visível no
módulo de Relatórios da conta (PRO+). Não é aviso automático ao responsável; é
registro consultável. Se a intenção for notificar o chefe de setor de forma ativa,
isso é trabalho novo e não está em nenhuma etapa.

### Etapa 44 — Frontend: travar os campos EMAIL e PDF

Hoje o checkbox EMAIL (`App.tsx:6113`) e o botão PDF não olham plano — o PDF só
tem `disabled` por `pdfExportAllowed`, que era `true` no FREE. Mesmo tratamento
visual do ACTIVE, que já mostra o cadeado.

> `feat: campos de email e pdf mostram a trava de plano`

**Feita em 2026-08-23.** `emailNotifyAllowed` e `reportOnVerifiedOnly` entraram no
`AccountDto` do Frontend. Comportamento por plano:

| | EMAIL | PDF | aviso na tela |
|---|---|---|---|
| FREE | desabilitado, `EMAIL ⛔` | desabilitado | — |
| Pro pessoal | ativo, tooltip do domínio | ativo, tooltip do domínio | ⚠ quando e-mail marcado ou já há resultado |
| Empresa / ENTERPRISE | ativo | ativo | — |

- `notify` vai para a API como `notify && canEmailNotify`: mesmo com estado velho no
  checkbox, não se pede notificação que o backend vai recusar
- O aviso de domínio só aparece quando a entrega é possível — e-mail marcado ou
  resultado na tela. Sem isso ficaria fixo no painel do Pro
- **Visitante não muda:** o botão PDF segue habilitado e responde "requer
  autenticação". É o convite para cadastrar, não uma trava de plano
- A tela de Agendamentos ganhou só o tooltip do domínio: agendar já é PRO+, então
  `emailNotifyAllowed` ali é sempre true

### Etapa 45 — Cardápio: refletir a política nova

A Etapa 28 entregou "PDF do scan ✓" nos três planos, que era verdade na época.
Vira:

| linha | Free | Pro | Empresa |
|---|---|---|---|
| PDF do scan | ✗ | ◑ só domínios verificados | ✓ |
| Notificação por e-mail | ✗ | ◑ só domínios verificados | ✓ |

> `feat: cardapio reflete pdf e email como recurso pago`

**Feita em 2026-08-24, no mesmo commit da Etapa 44** — a tela e o cardápio contam a
mesma regra, não faz sentido separar.

O cardápio foi de nove para dez linhas. O ◑ ganhou um segundo sentido, agora
documentado no comentário do `PLAN_DEFS`: marca recurso que **o plano libera e o
domínio limita**, não recurso pela metade. Rótulos por card em vez de um genérico —
"PDF do scan (só domínios verificados)" no Pro contra "PDF de qualquer domínio" na
Empresa, que é onde está o argumento de venda do tier de cima.

---

## Bloco E — Dívida técnica já identificada

### Etapa 39 — Revogar sessões após troca de senha

Verificado: **não existe** `password_changed_at` no `AppUser`. O JWT anterior segue
válido por até 24h depois da redefinição. Carimbo no usuário + conferência no filtro
JWT.

> `sec: redefinir senha invalida as sessoes antigas`

### Etapa 40 — Teste de integração da cadeia de segurança

`pom.xml` **não tem** `spring-security-test` nem H2 (confirmado). São 19 arquivos de
teste e nenhum sobe o filtro do Spring Security — foi por isso que o preflight 403
de CORS passou e custou uma rodada inteira. Vale fazer antes das etapas que mexem em
endpoint.

> `test: cobre a cadeia de filtros de seguranca com mockmvc`

**Feita em 2026-08-24.** `spring-security-test` + H2 no `pom.xml`, perfil `test` em
`src/test/resources/application-test.properties` (H2 em memória, segredo fixo de
teste, `dns.resolver=system` para não sondar rede no boot), e
`SecurityChainIntegrationTest` com 9 testes — 196 no total.

Os testes afirmam sobre **status e cabeçalho, nunca sobre corpo**: o que está sob
teste é quem responde primeiro, não o que o controller devolve.

**Achado 1 — rota fechada respondia 403, não 401. Corrigido junto.** Não havia
`AuthenticationEntryPoint`, então o `ExceptionTranslationFilter` caía no padrão. É
errado na semântica HTTP e tinha efeito real: o interceptor do Frontend só derruba
a sessão em 401, então **token expirado no meio da navegação deixava o usuário
preso** — toda chamada falhando, sem ser mandado para o login, até recarregar a
página. O que mascarava isso é `/auth/me` devolver 401 por conta própria, fazendo
só o caminho do boot funcionar. Quem está autenticado e não tem o papel continua
recebendo 403.

**Achado 2 — `/auth/login` sem e-mail responde 500.** Registrado como Etapa 46;
não entrou aqui por ser outro assunto.

### Etapa 41 — DKIM dirigido por evidência

Hoje sonda ~40 seletores conhecidos por força bruta. O `include:` do SPF e o destino
do MX revelam o provedor e permitem palpite dirigido.

> `perf: sonda de dkim usa o provedor revelado por spf e mx`

### Etapa 46 — Validar o corpo dos endpoints de autenticação

Achado pela Etapa 40. `POST /auth/login` com `{}` estoura
`NullPointerException` em `getEmail().toLowerCase()` e responde **500**. O
`LoginRequest` não tem anotação de validação nenhuma e o controller não usa
`@Valid` — o mesmo vale para `RegisterRequest`, que merece a mesma conferida.

Não é falha de segurança (o endpoint é público de propósito e nada vaza —
`server.error.include-*` está tudo desligado), mas 500 é resposta errada para
corpo malformado, e enche o log de stack trace de quem só mandou requisição torta.

> `fix: corpo invalido no login responde 400 em vez de 500`

**Feita em 2026-08-24.** A varredura mostrou que o problema era menor do que
parecia: `register` **já** tinha a guarda de campo obrigatório, `requestReset` e
`resetPassword` já eram null-safe, e `PasswordPolicy.validate` já recusa senha
nula. O `login` era o único endpoint fora do padrão.

Por isso **não** entrou `spring-boot-starter-validation`: uma dependência nova e
duas anotações para um caso que o resto do arquivo resolve com `if` explícito
seria introduzir um segundo jeito de fazer a mesma coisa. A guarda foi escrita
igual à do `register`, logo acima.

A conferência vem **antes** do throttle de propósito: requisição malformada não é
tentativa de login e não deve gastar o crédito de ninguém.

`AuthEndpointValidationTest` com 6 testes — 202 no total. Cobre login, register e
os dois de redefinição, para a assimetria não voltar.

---

## Ordem sugerida

1. **Etapa 0** — o Postgres tem prazo e o `.sql` bloqueia deploy
2. **Etapa 28** — dez linhas, corrige em produção a tela que vende o produto
3. **Etapas 31 e 32** — o assinante hoje não consegue cancelar
4. **Etapa 40** — rede de segurança antes de mexer em endpoint
5. **Etapas 29 e 30** — mata a duplicação do cardápio
6. **Bloco C (33 → 36)** — o item grande, destravado com o inglês decidido
7. **Etapas 39 e 41** — dívida sem prazo

Fora do plano: **Bloco D (37 e 38)**, adiado por decisão de 2026-08-23.

Uma dependência de ordem entre blocos: a **Etapa 36** extrai as strings do
`App.tsx`, e as **etapas 28, 30, 31 e 32** escrevem strings novas nesse mesmo
arquivo. Fazer o bloco A e o B antes evita traduzir texto que ainda vai mudar — que
é a ordem sugerida acima.
