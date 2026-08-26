# Escopo para a próxima sessão

Levantado em 2026-08-23, ao fim da sessão que estabilizou DNS, e-mail, planos e
billing. Cobre os dois repositórios (`Backend` e `Frontend`).

---

## 1. Cardápio de planos desatualizado — CONFIRMADO

O `PLAN_DEFS` (Frontend/src/App.tsx) lista seis itens: scans/dia, Exportar PDF,
Módulo Changes, Gráfico histórico, Active Scan, Multi-usuário.

Durante esta sessão foram criadas **quatro diferenças de plano que não aparecem
no cardápio**, todas já valendo em produção:

| recurso | FREE | PRO | ENTERPRISE | onde vive |
|---|---|---|---|---|
| **Detalhe do achado** (impacto, correção, breakdown) | ✗ borrado | ✓ | ✓ | `ScanEntitlementService` |
| **Agendamentos** | ✗ (limite 0) | 10 | ilimitado | `Plan.scheduledScanLimit` |
| **Cadastro de domínio** | ✗ | ✓ | ✓ | `Plan.domainRegistrationAllowed` |
| **Relatórios da conta** (auditoria, PDF executivo, página de status) | ✗ | ✓ | ✓ | `Plan.reportsModuleAllowed` |

O primeiro é o mais grave: **o detalhe do achado é o principal diferencial pago**
do produto e não está no cardápio. Um FREE vê título borrado e cadeado sem que a
tela de planos explique que é isso que ele compra.

Atenção também ao item "Exportar PDF": hoje aparece ✓ para FREE e está correto
(PDF do scan), mas o **PDF executivo** virou PRO+. O rótulo genérico ficou
ambíguo e precisa ser desmembrado.

**Fonte da verdade:** `Backend/src/main/java/com/joao/cyberaudit/model/Plan.java`.
Vale considerar derivar o cardápio dos flags do `AccountDto` em vez de manter uma
lista paralela em código — foi a duplicação que permitiu a divergência.

---

## 2. "Seu plano atual" — PARCIALMENTE OK

**Funciona** no retorno do checkout: `BillingReturnPage` faz polling em
`/billing/subscription` e, ao ver `AUTHORIZED`, redireciona com
`window.location.href = "/"`. O reload recarrega `/auth/me` e o plano aparece
atualizado.

**Não verificado / provável lacuna:**

- **Cancelamento.** `/billing/cancel` altera o plano no servidor, mas o objeto
  `user` do `AuthContext` continua em memória. Sem reload, o cardápio segue
  mostrando o plano antigo como atual.
- **Mudança fora do fluxo.** Webhook que rebaixa a conta (assinatura cancelada
  pelo MP, pagamento recusado) enquanto o usuário está logado não chega à tela.

**Sugestão:** expor um `refreshUser()` no `AuthContext` que refaz `/auth/me`, e
chamá-lo após cancelar e ao abrir o `PlansModal`. Evita depender de reload.

---

## 3. Internacionalização (i18n)

Requisito válido para escala global, mas o esforço está num lugar
contraintuitivo — vale dimensionar antes de começar.

**A parte visível (menor):** strings da interface, hoje inline no `App.tsx`
(arquivo de ~6.000 linhas). Trabalhoso, mas mecânico.

**A parte que decide o projeto (maior):** o conteúdo do produto é gerado no
**backend, em português** — título, impacto e correção de cada achado, montados
em `ScoreService`, `HeaderService`, `DnsSecurityService` e afins. Traduzir só a
casca deixaria o cliente estrangeiro lendo a interface em inglês e o laudo em
português. Some-se a isso o PDF e os e-mails.

**Ponto de alavanca:** todo achado já tem **ID estável** (`DNS_EMAIL_SPOOFING`,
`HSTS_MISSING`, `CSP_MISSING`…). Esses IDs são a chave natural de um catálogo de
mensagens. O caminho de menor risco:

1. Extrair título/impacto/correção para um catálogo indexado por ID
2. Backend passa a devolver ID + parâmetros, não texto pronto
3. A tradução vira arquivo de recurso por idioma, sem tocar na lógica de scan
4. Só então traduzir a interface

Fazer na ordem inversa (interface primeiro) dá sensação de progresso e não
resolve o problema real.

---

## 4. Mercado Pago para escala global — NÃO É ADEQUADO SOZINHO

O MP é forte em América Latina (Brasil, Argentina, México, Chile, Colômbia,
Peru, Uruguai) e tem vantagem real no Brasil: PIX, boleto e cartões locais. Fora
da região, não é uma opção viável para receber.

**Duas famílias de alternativa, com implicações bem diferentes:**

| | exemplo | quem lida com imposto |
|---|---|---|
| Gateway | Stripe | **você** — VAT europeu, sales tax americano, notas |
| Merchant of Record | Paddle, Lemon Squeezy, Polar | **eles** — vendem em nome próprio |

Para operação enxuta vendendo software mundo afora, o MoR costuma valer a taxa
maior: o VAT europeu sozinho é obrigação recorrente por país. Um gateway é mais
barato por transação e mais caro em contabilidade.

**Recomendação:** manter o MP para o Brasil e adicionar um segundo provedor para
o exterior. É arranjo comum e preserva o PIX, que nenhum internacional oferece
bem.

**Impacto no código:** `BillingService` chama `MercadoPagoService` diretamente.
Um segundo provedor pede a mesma separação que já fizemos no e-mail — uma
interface de transporte (`EmailSender` → `SmtpEmailSender`/`ResendEmailSender`)
com implementação escolhida por configuração. O modelo já está no repositório e
funcionou bem.

Antes de escolher provedor, decidir **em que moeda cobrar**: preço fixo em USD,
ou preço por região. Isso muda o desenho e é decisão de negócio, não técnica.

---

## Pendências operacionais desta sessão

- [ ] `MP_ACCESS_TOKEN` de volta para **produção** depois dos testes com conta de
      teste — conferir a linha `[MercadoPago]` no boot, que informa o ambiente
- [ ] Rodar `deploy/audit-action-check.sql` **antes** do deploy que adiciona
      `PASSWORD_RESET_REQUESTED`/`PASSWORD_RESET_COMPLETED` ao enum, se ainda não
      foi feito — sem isso a redefinição de senha quebra na gravação do log
- [ ] `deploy/cleanup-free-domains.sql` — domínios de contas FREE ainda na base
- [ ] Postgres do Render: plano gratuito **expira ~30 dias após a criação**
      (criado por volta de 12/08). Sem upgrade ou backup, os dados somem
- [ ] Boot de ~210s no free tier: toda instância que dorme causa ~3min de
      indisponibilidade. É o maior problema operacional em aberto

## Melhorias identificadas e não implementadas

- **Revogar sessões após troca de senha.** JWT antigo continua válido por até 24h
  depois da redefinição. Exige carimbo `password_changed_at` no usuário conferido
  pelo filtro JWT. Documentado em `PasswordResetService`
- **DKIM dirigido por evidência.** Hoje sonda ~40 seletores conhecidos. O
  `include:` do SPF e o destino do MX revelam o provedor de e-mail e permitiriam
  palpite dirigido em vez de força bruta
- **Teste de integração da cadeia de segurança.** O bug de CORS (preflight 403)
  passou porque não há teste que suba o filtro do Spring Security. Exige
  `spring-security-test` + H2 no `pom.xml`
